//! Runs a test's JavaScript (the GUI's `pure.js` plus a harness) in an embedded
//! engine, so the check runs on every machine instead of only where `node` is
//! installed. `console.log` lines come back as the output, one per line.

use boa_engine::{Context, Source};

const CONSOLE: &str = r#"
var __log = [];
var console = {
    log: function () {
        __log.push(Array.prototype.map.call(arguments, function (a) { return String(a) }).join(" "))
    }
};
"#;

/// The lines the program logged, each ending in `\n`. A program the engine
/// rejects or that throws fails the test with the engine's message.
pub fn run_js(program: &str) -> String {
    // `.pragma library` is QML, not JavaScript.
    let program: String = program
        .lines()
        .map(|line| {
            if line.trim_start().starts_with(".pragma") {
                ""
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    let mut context = Context::default();
    for (what, code) in [("console", CONSOLE), ("harness", program.as_str())] {
        if let Err(e) = context.eval(Source::from_bytes(code)) {
            panic!("the {what} script failed: {e:?}");
        }
    }
    let joined = context
        .eval(Source::from_bytes(
            "__log.length ? __log.join('\\n') + '\\n' : ''",
        ))
        .unwrap_or_else(|e| panic!("reading the log failed: {e:?}"));
    joined
        .to_string(&mut context)
        .unwrap_or_else(|e| panic!("the log is not text: {e:?}"))
        .to_std_string_escaped()
}
