#![allow(clippy::expect_used)]

//! The Logs view showed each line's category and event type as the service's
//! slugs (`service`, `ipc-push`, `conn-trace`) on a Russian screen. They are
//! named in the reader's language; a slug no locale names yet shows as it is.

#[path = "support/js.rs"]
mod js;
#[path = "support/qml_functions.rs"]
mod qml_functions;

#[test]
fn a_log_slug_is_named_and_an_unknown_one_shows_as_it_is() {
    let output = js::run_js(&format!(
        "{}\n\
         var names = {{ 'diag.logs.kind.ipc-push': 'Обновления статуса',\n\
                        'diag.logs.kind.dns-resolver': 'DNS-резолвер',\n\
                        'diag.logs.kind.cache-store': 'Кэш',\n\
                        'diag.logs.category.user-action': 'Действия пользователя' }};\n\
         function tr(key, fallback) {{ return names[key] !== undefined ? names[key] : fallback }}\n\
         console.log(logSlugText(tr, 'diag.logs.kind.', 'ipc-push'));\n\
         console.log(logSlugText(tr, 'diag.logs.kind.', 'dns_resolver'));\n\
         console.log(logSlugText(tr, 'diag.logs.kind.', 'cache.store'));\n\
         console.log(logSlugText(tr, 'diag.logs.category.', 'user_action'));\n\
         console.log(logSlugText(tr, 'diag.logs.kind.', 'brand-new'));\n\
         console.log('[' + logSlugText(tr, 'diag.logs.kind.', '') + ']');",
        qml_functions::pure()
    ));
    assert_eq!(
        output,
        "Обновления статуса\nDNS-резолвер\nКэш\nДействия пользователя\nbrand-new\n[]\n"
    );
}

#[test]
fn the_log_table_names_its_categories_and_event_types() {
    let source = qml_functions::read("sections/LogsSection.qml");
    for prefix in ["diag.logs.category.", "diag.logs.kind."] {
        assert!(
            source.contains(&format!("Pure.logSlugText(root.tr, \"{prefix}\"")),
            "the log table shows {prefix}* as raw slugs"
        );
    }
}
