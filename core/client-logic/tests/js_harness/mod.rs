//! Runs the GUI's own `pure.js` / `rules.js` in an embedded JS engine and
//! feeds both implementations the vectors under `tests/vectors/`.

use std::path::{Path, PathBuf};

use boa_engine::{Context, Source};
use serde_json::Value;

/// The export moment both writers stamp: JS through the `Date` shim below.
pub const EXPORTED_AT: &str = "2026-01-02T03:04:05.000Z";

/// Stand-ins for the C++ bridge's IDN callbacks, defined identically on both
/// sides: a non-ASCII host gains an `ace:` prefix, `ace-fails.example` encodes
/// to nothing (the caller then keeps the value), and decoding strips the prefix.
const PRELUDE: &str = r#"
var __model = function (rows) {
    return { count: rows.length, get: function (i) { return rows[i] } }
};
var __aceEncode = function (v) {
    if (v === "ace-fails.example") return "";
    return /[^\x00-\x7f]/.test(v) ? "ace:" + v : v
};
var __aceDecode = function (v) {
    return v.indexOf("ace:") === 0 ? v.substring(4) : v
};
Date = function () {
    return { toISOString: function () { return "2026-01-02T03:04:05.000Z" } }
};
"#;

pub fn ace_encode(value: &str) -> String {
    if value == "ace-fails.example" {
        String::new()
    } else if value.is_ascii() {
        value.to_owned()
    } else {
        format!("ace:{value}")
    }
}

pub fn ace_decode(value: &str) -> String {
    value.strip_prefix("ace:").unwrap_or(value).to_owned()
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// One GUI library loaded into its own engine.
pub struct JsLib {
    context: Context,
    name: &'static str,
}

impl JsLib {
    pub fn pure() -> Self {
        Self::load("pure.js")
    }

    pub fn rules() -> Self {
        Self::load("rules.js")
    }

    fn load(file: &'static str) -> Self {
        let path = repo_root().join("apps/desktop/qml/lib").join(file);
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        // `.pragma library` is QML, not JavaScript; blanking the line keeps
        // the engine's line numbers equal to the file's.
        let script = source
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
        let mut lib = Self {
            context: Context::default(),
            name: file,
        };
        lib.run(&script);
        lib.run(PRELUDE);
        lib
    }

    fn run(&mut self, code: &str) -> boa_engine::JsValue {
        self.context
            .eval(Source::from_bytes(code))
            .unwrap_or_else(|e| panic!("{}: evaluation failed: {e:?}", self.name))
    }

    /// The value of a JS expression, through `JSON.stringify`; `undefined`
    /// reads as `null`.
    pub fn eval_json(&mut self, expr: &str) -> Value {
        let value = self.run(&format!("JSON.stringify({{ r: ({expr}) }})"));
        let text = value
            .to_string(&mut self.context)
            .unwrap_or_else(|e| panic!("{}: `{expr}` is not a string: {e:?}", self.name))
            .to_std_string_escaped();
        let parsed: Value = serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("{}: `{expr}` gave bad JSON {text}: {e}", self.name));
        parsed.get("r").cloned().unwrap_or(Value::Null)
    }
}

/// A JSON value as a JS literal.
pub fn lit(value: &Value) -> String {
    value.to_string()
}

/// A member of `input` as a JS literal, `undefined` when absent.
pub fn arg(input: &Value, key: &str) -> String {
    input.get(key).map_or_else(|| "undefined".to_owned(), lit)
}

/// A string member of `input`, empty when absent or not a string.
pub fn text<'a>(input: &'a Value, key: &str) -> &'a str {
    input.get(key).and_then(Value::as_str).unwrap_or("")
}

pub struct Case {
    pub name: String,
    pub input: Value,
    pub expected: Option<Value>,
}

/// The vector file `tests/vectors/<file>.json`: the whole document (for
/// shared fixtures such as a base row) and its cases.
pub fn load_vectors(file: &str) -> (Value, Vec<Case>) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors")
        .join(format!("{file}.json"));
    let raw =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let document: Value =
        serde_json::from_str(&raw).unwrap_or_else(|e| panic!("{}: not JSON: {e}", path.display()));
    let cases = document["cases"]
        .as_array()
        .unwrap_or_else(|| panic!("{}: no `cases` array", path.display()))
        .iter()
        .map(|case| Case {
            name: text(case, "name").to_owned(),
            input: case.get("input").cloned().unwrap_or(Value::Null),
            expected: case.get("expected").cloned(),
        })
        .collect();
    (document, cases)
}

/// Runs every case of `file` through the JS expression and the Rust function,
/// and fails listing each case where they disagree with each other or with
/// the case's `expected`.
pub fn check(
    file: &str,
    js: &mut JsLib,
    js_expr: impl Fn(&Value) -> String,
    rust: impl Fn(&Value) -> Value,
) {
    let (_, cases) = load_vectors(file);
    check_cases(file, &cases, js, js_expr, rust);
}

pub fn check_cases(
    file: &str,
    cases: &[Case],
    js: &mut JsLib,
    js_expr: impl Fn(&Value) -> String,
    rust: impl Fn(&Value) -> Value,
) {
    assert!(cases.len() >= 8, "{file}: only {} vectors", cases.len());
    let mut failures = Vec::new();
    for case in cases {
        let from_js = js.eval_json(&js_expr(&case.input));
        let from_rust = rust(&case.input);
        if from_js != from_rust {
            failures.push(format!(
                "{file} / {}:\n  JS:   {from_js}\n  Rust: {from_rust}",
                case.name
            ));
        } else if let Some(expected) = case.expected.as_ref().filter(|e| **e != from_js) {
            failures.push(format!(
                "{file} / {}: both gave {from_js}, the vector expects {expected}",
                case.name
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// `patch` laid over `base`, objects merged member by member.
pub fn merged(base: &Value, patch: &Value) -> Value {
    match (base, patch) {
        (Value::Object(base), Value::Object(patch)) => {
            let mut out = base.clone();
            for (key, value) in patch {
                let next = out
                    .get(key)
                    .map_or_else(|| value.clone(), |current| merged(current, value));
                out.insert(key.clone(), next);
            }
            Value::Object(out)
        }
        _ => patch.clone(),
    }
}
