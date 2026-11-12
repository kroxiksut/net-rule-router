//! Retained probe evidence for both discovery episode surfaces (`pure.js`).

use serde_json::{json, Value};

fn integer(value: &Value, max: f64) -> Option<u64> {
    let number = value.as_f64()?;
    (number.is_finite() && number >= 0.0 && number <= max && number.fract() == 0.0)
        .then_some(number as u64)
}

/// Presentation facts from the service's owner-scoped queue snapshot. A delay
/// only belongs to a time gate, never to worker capacity or queue position.
#[must_use]
pub fn discovery_probe_queue(queue: &Value) -> Value {
    let Some(kind) = queue["wait-kind"].as_str().filter(|kind| {
        matches!(
            *kind,
            "rate" | "workers" | "cooldown" | "ahead" | "scheduled" | "resources" | "rules"
        )
    }) else {
        return Value::Null;
    };
    let Some(ahead) = integer(&queue["queued-ahead"], f64::from(u32::MAX)) else {
        return Value::Null;
    };
    let seconds = if matches!(kind, "rate" | "cooldown") {
        integer(&queue["eligible-in-ms"], 9_007_199_254_740_991.0).map(|ms| ms.div_ceil(1000))
    } else {
        None
    };
    let started = integer(
        &queue["last-probe-started-unix-ms"],
        8_640_000_000_000_000.0,
    )
    .filter(|at| *at > 0);
    json!({"kind":kind,"ahead":ahead,"seconds":seconds,"started":started})
}

/// The latest retained, explicitly measured probe outcome. Queue, consent and
/// inconclusive decisions can happen before a network call and are not results.
/// Absence means only that this bounded history contains no such outcome.
#[must_use]
pub fn discovery_previous_probe(history: &Value) -> Value {
    let Some(steps) = history.as_array() else {
        return Value::Null;
    };
    for step in steps.iter().rev().take(8) {
        if step["stage"].as_str() != Some("probe") {
            continue;
        }
        let Some(reason) = step["reason"].as_str().filter(|reason| {
            matches!(
                *reason,
                "primary-responds"
                    | "secondary-failed"
                    | "https-unconfirmed"
                    | "http-answered"
                    | "http-no-answer"
                    | "http-client-error"
                    | "http-server-error"
            )
        }) else {
            continue;
        };
        let Some(at) = integer(&step["at-unix-ms"], 8_640_000_000_000_000.0).filter(|at| *at > 0)
        else {
            continue;
        };
        return json!({"reason": reason, "at-unix-ms": at});
    }
    Value::Null
}
