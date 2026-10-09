//! A warning in the notifications centre is read before the news: a card that
//! needs the user's hand ("the service does not have your settings") must not
//! sit under informational cards, below the fold.
#![allow(clippy::expect_used)]

use std::path::Path;

fn qml(relative: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../qml")
        .join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

#[test]
fn the_centre_lists_warnings_first() {
    let main = qml("Main.qml");
    let at = main
        .find("readonly property var activeNotifications:")
        .expect("activeNotifications");
    let body = &main[at..];
    let end = body.find("\n    }").expect("end of the list");
    assert!(body[..end].contains("return Pure.noticesWarningsFirst(out)"));
}

#[test]
fn the_order_is_stable_within_each_group() {
    let pure = qml("lib/pure.js");
    let at = pure
        .find("function noticesWarningsFirst(")
        .expect("noticesWarningsFirst");
    let body = &pure[at..];
    let end = body.find("\n}").expect("end of the function");
    let body = &body[..end];
    assert!(body.contains("warnings.push(n)") && body.contains("rest.push(n)"));
    assert!(body.contains("return warnings.concat(rest)"));
}
