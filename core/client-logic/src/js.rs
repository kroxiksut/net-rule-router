//! The JavaScript conversions the GUI helpers lean on, spelled once so every
//! port agrees with its JS twin on loose input as well as on clean input.

use serde_json::Value;

/// ECMAScript `WhiteSpace` and `LineTerminator`: Unicode `White_Space`
/// without NEL, plus the byte-order mark.
pub(crate) fn is_whitespace(c: char) -> bool {
    c == '\u{FEFF}' || (c.is_whitespace() && c != '\u{85}')
}

/// `String.prototype.trim`.
pub(crate) fn trim(s: &str) -> &str {
    s.trim_matches(is_whitespace)
}

/// `!!value`.
pub(crate) fn is_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        Value::String(s) => !s.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

/// `String(value)`.
pub(crate) fn to_display_string(value: &Value) -> String {
    match value {
        Value::Null => "null".to_owned(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.as_f64().map_or_else(|| n.to_string(), number_to_string),
        Value::String(s) => s.clone(),
        Value::Array(items) => items
            .iter()
            .map(|item| {
                if item.is_null() {
                    String::new()
                } else {
                    to_display_string(item)
                }
            })
            .collect::<Vec<_>>()
            .join(","),
        Value::Object(_) => "[object Object]".to_owned(),
    }
}

/// `String(number)`. Integral values below 1e21 print as integers, as in JS;
/// other values use the shortest round-trip form, which matches JS everywhere
/// except the exponent ranges (below 1e-6), where JS writes `1e-7`.
fn number_to_string(n: f64) -> String {
    if n.is_nan() {
        "NaN".to_owned()
    } else if n.is_infinite() {
        let text = if n > 0.0 { "Infinity" } else { "-Infinity" };
        text.to_owned()
    } else if n == 0.0 {
        "0".to_owned()
    } else if n.fract() == 0.0 && n.abs() < 1e21 {
        format!("{n:.0}")
    } else {
        n.to_string()
    }
}

/// `Number(value)`.
pub(crate) fn to_number(value: &Value) -> f64 {
    match value {
        Value::Null => 0.0,
        Value::Bool(b) => f64::from(u8::from(*b)),
        Value::Number(n) => n.as_f64().unwrap_or(f64::NAN),
        Value::String(s) => string_to_number(s),
        Value::Array(_) => string_to_number(&to_display_string(value)),
        Value::Object(_) => f64::NAN,
    }
}

fn string_to_number(s: &str) -> f64 {
    let t = trim(s);
    if t.is_empty() {
        return 0.0;
    }
    let radix = match t.get(..2) {
        Some("0x" | "0X") => Some(16),
        Some("0o" | "0O") => Some(8),
        Some("0b" | "0B") => Some(2),
        _ => None,
    };
    if let Some(radix) = radix {
        let digits = &t[2..];
        if digits.is_empty() {
            return f64::NAN;
        }
        return digits
            .chars()
            .try_fold(0.0_f64, |acc, c| {
                c.to_digit(radix)
                    .map(|d| acc * f64::from(radix) + f64::from(d))
            })
            .unwrap_or(f64::NAN);
    }
    match t {
        "Infinity" | "+Infinity" => return f64::INFINITY,
        "-Infinity" => return f64::NEG_INFINITY,
        _ => {}
    }
    // Rust's parser also takes `inf` / `nan`, which JS does not.
    if t.bytes()
        .all(|b| b.is_ascii_digit() || matches!(b, b'.' | b'e' | b'E' | b'+' | b'-'))
    {
        t.parse().unwrap_or(f64::NAN)
    } else {
        f64::NAN
    }
}

/// `ToInt32`, what `value | 0` applies.
pub(crate) fn to_int32(n: f64) -> i32 {
    if !n.is_finite() {
        return 0;
    }
    let wrapped = n.trunc().rem_euclid(4_294_967_296.0);
    // `wrapped` lies in [0, 2^32): exact as u32, reinterpreted as i32.
    (wrapped as u32) as i32
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn int32_wraps_like_js() {
        assert_eq!(to_int32(4_294_967_297.0), 1);
        assert_eq!(to_int32(2_147_483_648.0), i32::MIN);
        assert_eq!(to_int32(-1.9), -1);
        assert_eq!(to_int32(f64::NAN), 0);
    }

    #[test]
    fn numbers_read_like_js() {
        assert_eq!(to_number(&json!(" 0x1F ")), 31.0);
        assert_eq!(to_number(&json!("")), 0.0);
        assert!(to_number(&json!("inf")).is_nan());
        assert_eq!(to_number(&json!([7])), 7.0);
        assert_eq!(to_number(&json!(true)), 1.0);
    }

    #[test]
    fn strings_print_like_js() {
        assert_eq!(to_display_string(&json!(127.0)), "127");
        assert_eq!(to_display_string(&json!(1.5)), "1.5");
        assert_eq!(to_display_string(&json!([1, null, "a"])), "1,,a");
        assert_eq!(to_display_string(&json!({})), "[object Object]");
    }
}
