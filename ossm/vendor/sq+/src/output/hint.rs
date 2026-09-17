//! Formats hints for users.

use std::fmt;
use std::io::IsTerminal;
use std::io::Write;

/// Formats a hint for the user.
pub struct Hint {
    /// Whether to suppress printing the hint.
    quiet: bool,

    /// Whether this is the first hint in this hint block.
    first: bool,
}

impl Hint {
    /// Constructs a new hint, optionally suppressing it.
    pub fn new(quiet: bool) -> Self {
        Hint {
            quiet,
            first: true,
        }
    }

    /// Displays a message to the user.
    ///
    /// It will be prefixed with "Hint: ", and should either end in a
    /// full stop or colon, depending on whether or not a command hint
    /// follows.
    pub fn hint(mut self, msg: fmt::Arguments) -> Self {
        if ! self.quiet {
            weprintln!();
            weprintln!(
                initial_indent=if self.first { "Hint: " } else { "      " },
                subsequent_indent="      ",
                "{}", msg);
            self.first = false;
        }
        self
    }

    /// Suggests an `sq` command to the user.
    pub fn sq(self) -> Command {
        Command::new(self, "sq")
    }

    /// Suggests a free-form command to the user.
    ///
    /// Note: if you want to suggest an `sq` invocation, use
    /// [`Hint::sq`] instead.
    pub fn command(self, argv0: &str) -> Command {
        Command::new(self, argv0)
    }
}

/// A structured command hint.
pub struct Command {
    hint: Hint,
    args: Vec<(String, Option<String>)>,
}

impl Command {
    fn new(hint: Hint, argv0: &str) -> Self {
        Command {
            hint,
            args: vec![(argv0.into(), None)],
        }
    }

    /// Adds `arg` to the command.
    pub fn arg<S: ToString>(mut self, arg: S) -> Self {
        self.args.push((arg.to_string(), None));
        self
    }

    /// Adds `arg` to the command, but show the user the replacement.
    pub fn arg_hidden<S: ToString, R: ToString>(
        mut self, arg: S, replacement: R)
        -> Self
    {
        self.args.push((arg.to_string(), Some(replacement.to_string())));
        self
    }

    /// Adds an argument `arg` with value to the command.
    pub fn arg_value<S: ToString, V: ToString>(mut self, arg: S, value: V)
                                               -> Self
    {
        self.args.push(
            (format!("{}={}", arg.to_string(), value.to_string()),
             None));
        self
    }

    /// Adds an argument `arg` with value to the command, but show the
    /// user the replacement value.
    pub fn arg_value_hidden<S: ToString, V: ToString, R: ToString>(
        mut self, arg: S, value: V, replacement_value: R)
        -> Self
    {
        self.args.push(
            (format!("{}={}", arg.to_string(), value.to_string()),
             Some(format!("{}={}",
                          arg.to_string(),
                          replacement_value.to_string()))));
        self
    }

    /// Emits the command hint.
    pub fn done(self) -> Hint {
        if ! self.hint.quiet {
            // If we're connected to a terminal, flush stdout to
            // reduce the chance of incorrectly interleaving output
            // and hints.
            let mut stdout = std::io::stdout();
            if stdout.is_terminal() {
                // Best effort.
                let _ = stdout.flush();
            }

            let width = crate::output::wrapping::stderr_terminal_width();

            let args = self.args.iter()
                .map(|(arg, replacement)| {
                    if let Some(replacement) = replacement {
                        replacement
                    } else {
                        arg
                    }
                })
                .collect::<Vec<_>>();

            eprintln!();
            eprintln!("{}", crate::cli::examples::wrap_command(
                &args, &[], "  ", width, "    ", width));
        }

        if cfg!(debug_assertions) && self.args[0].0 == "sq" {
            let cli = crate::cli::build(false);

            if let Err(e)
                = cli.try_get_matches_from(self.args.iter().map(|(a, _)| a))
            {
                panic!("bad hint, parsing {}", e);
            }
        }

        self.hint
    }
}
