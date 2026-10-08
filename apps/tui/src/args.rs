//! Command-line options. Parsing is pure; the environment is read by the caller
//! and passed in, so the precedence rules are tested without touching it.

/// What the user asked for on the command line and in the environment.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Options {
    pub lang: Option<String>,
    /// Line mode: no redrawing, every change printed as a new line.
    pub plain: bool,
    pub no_color: bool,
    /// Plain characters instead of frame lines.
    pub ascii: bool,
    /// Open the first-run setup screen first.
    pub wizard: bool,
    /// Sound the terminal bell on a new notification.
    pub bell: bool,
}

/// What `main` does with the command line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Invocation {
    Run(Options),
    Help,
    Version,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArgError {
    Unknown(String),
    MissingValue(&'static str),
}

/// The environment variables that also set options.
#[derive(Clone, Copy, Debug, Default)]
pub struct Env<'a> {
    /// `NO_COLOR`: any non-empty value turns colour off (no-color.org).
    pub no_color: Option<&'a str>,
    /// `NRR_TUI_PLAIN=1` selects line mode.
    pub plain: Option<&'a str>,
}

pub fn parse(args: &[String], env: Env<'_>) -> Result<Invocation, ArgError> {
    let mut options = Options {
        no_color: env.no_color.is_some_and(|v| !v.is_empty()),
        plain: env.plain.is_some_and(|v| v.trim() == "1"),
        ..Options::default()
    };
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--plain" => options.plain = true,
            "--no-color" => options.no_color = true,
            "--ascii" => options.ascii = true,
            "--wizard" => options.wizard = true,
            "--bell" => options.bell = true,
            "--help" | "-h" => return Ok(Invocation::Help),
            "--version" | "-V" => return Ok(Invocation::Version),
            "--lang" => {
                let value = rest
                    .next()
                    .filter(|v| !v.starts_with("--") && !v.is_empty())
                    .ok_or(ArgError::MissingValue("--lang"))?;
                options.lang = Some(value.clone());
            }
            other => match other.strip_prefix("--lang=") {
                Some("") => return Err(ArgError::MissingValue("--lang")),
                Some(value) => options.lang = Some(value.to_string()),
                None => return Err(ArgError::Unknown(other.to_string())),
            },
        }
    }
    Ok(Invocation::Run(options))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(args: &[&str], env: Env<'_>) -> Options {
        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        match parse(&args, env) {
            Ok(Invocation::Run(options)) => options,
            other => panic!("expected options, got {other:?}"),
        }
    }

    #[test]
    fn flags_are_read() {
        let o = run(
            &[
                "--plain",
                "--no-color",
                "--ascii",
                "--wizard",
                "--bell",
                "--lang",
                "ru",
            ],
            Env::default(),
        );
        assert!(o.plain && o.no_color && o.ascii && o.wizard && o.bell);
        assert_eq!(o.lang.as_deref(), Some("ru"));
        assert_eq!(
            run(&["--lang=en"], Env::default()).lang.as_deref(),
            Some("en")
        );
    }

    #[test]
    fn the_environment_sets_plain_and_no_color() {
        let o = run(
            &[],
            Env {
                no_color: Some("1"),
                plain: Some("1"),
            },
        );
        assert!(o.plain && o.no_color);
        let o = run(
            &[],
            Env {
                no_color: Some(""),
                plain: Some("0"),
            },
        );
        assert!(!o.plain && !o.no_color);
    }

    #[test]
    fn bad_input_is_named() {
        let args = vec!["--colour".to_string()];
        assert_eq!(
            parse(&args, Env::default()),
            Err(ArgError::Unknown("--colour".into()))
        );
        let args = vec!["--lang".to_string()];
        assert_eq!(
            parse(&args, Env::default()),
            Err(ArgError::MissingValue("--lang"))
        );
    }
}
