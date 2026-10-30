// Included by the Windows build scripts and by the test that holds its order.
// Windows version fields take numbers only; without the pre-release in one of
// them, alpha.1 installs over alpha.2 as "the same version".

/// The pre-release part of a cargo version as one number, oldest lowest:
/// `dev` 0, `alpha[.N]` 1+N, `beta[.N]` 30+N, `rc[.N]` 60+N, and a release 99.
/// A stage or number outside that is refused, so a version the installers
/// cannot order stops the build instead of shipping. Never renumber: installed
/// builds carry these numbers, and a new build must still rank above them.
#[allow(dead_code)]
pub fn prerelease_rank(pre: &str) -> Result<u16, String> {
    if pre.is_empty() {
        return Ok(99);
    }
    let (stage, number) = match pre.split_once('.') {
        Some((stage, number)) => (stage, Some(number)),
        None => (pre, None),
    };
    let number: u16 = match number {
        None => 0,
        Some(n) => n
            .parse()
            .map_err(|_| format!("pre-release '{pre}': '{n}' is not a number"))?,
    };
    let (base, most) = match stage.to_ascii_lowercase().as_str() {
        "dev" if number == 0 => return Ok(0),
        "alpha" => (1, 28),
        "beta" => (30, 29),
        "rc" => (60, 29),
        _ => {
            return Err(format!(
                "pre-release '{pre}' has no place in the version order"
            ))
        }
    };
    if number > most {
        return Err(format!("pre-release '{pre}': at most {most} of this stage"));
    }
    Ok(base + number)
}
