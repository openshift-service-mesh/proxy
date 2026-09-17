//! A framework to format and check examples.
//!
//! The help text for subcommands includes examples.  That's great.
//! But, it is even better when they are tested.  This module defines
//! data structures to describe the examples, mechanisms to format the
//! examples, and infrastructure to execute the examples.

use std::collections::BTreeMap;

use clap::builder::IntoResettable;
use clap::builder::Resettable;

/// A command that is executed by the integration test, but not shown
/// in the manual pages.
pub struct Setup<'a> {
    pub command: &'a [ &'a str ],
}

/// Builds up setup actions in an extensible way.
pub struct SetupBuilder<'a> {
    setup: Setup<'a>,
}

impl<'a> SetupBuilder<'a> {
    /// Returns a new setup builder.
    const fn new() -> Self {
        SetupBuilder {
            setup: Setup {
                command: &[],
            }
        }
    }

    /// Provides the command as slice.
    ///
    /// It'd be nice to provide a per-argument interface, but that
    /// requires some ingenuity for it to stay const.
    pub const fn command(mut self, command: &'a [&'a str]) -> Self {
        self.setup.command = command;
        self
    }

    /// Finishes building the setup action.
    pub const fn build(self) -> Action<'a> {
        assert!(! self.setup.command.is_empty());
        Action::Setup(self.setup)
    }
}

/// A command that is executed by the integration test, and shown in
/// the manual pages.
pub struct Example<'a> {
    // A human-readable comment.
    pub comment: &'a str,
    pub command: &'a [ &'a str ],
    pub hide: &'a [ &'a str ],
}

/// Builds up example actions in an extensible way.
pub struct ExampleBuilder<'a> {
    example: Example<'a>,
}

impl<'a> ExampleBuilder<'a> {
    /// Returns a new example builder.
    const fn new() -> Self {
        ExampleBuilder {
            example: Example {
                comment: "",
                command: &[],
                hide: &[],
            },
        }
    }

    /// Provides the comment.
    ///
    /// It'd be nice to provide a per-argument interface, but that
    /// requires some ingenuity for it to stay const.
    pub const fn comment(mut self, comment: &'a str) -> Self {
        self.example.comment = comment;
        self
    }

    /// Provides the command as slice.
    ///
    /// It'd be nice to provide a per-argument interface, but that
    /// requires some ingenuity for it to stay const.
    pub const fn command(mut self, command: &'a [&'a str]) -> Self {
        self.example.command = command;
        self
    }

    /// Hides the parameters in the output
    ///
    /// Skip these parameters when generating human readable output
    #[allow(unused)]
    pub const fn hide(mut self, hide: &'a [&'a str]) -> Self {
        self.example.hide = hide;
        self
    }

    /// Finishes building the example action.
    ///
    /// The example will be executed by the test.
    pub const fn build(self) -> Action<'a> {
        assert!(! self.example.comment.is_empty());
        assert!(! self.example.command.is_empty());
        Action::Example(self.example)
    }

    /// Finishes building the example action, marking it for syntax
    /// checking only.
    ///
    /// The example will not be executed by the test, but the syntax
    /// will be checked using our command line parser.
    pub const fn syntax_check(self) -> Action<'a> {
        assert!(! self.example.comment.is_empty());
        assert!(! self.example.command.is_empty());
        Action::SyntaxCheck(self.example)
    }
}

/// An action to execute.
#[allow(dead_code)]
pub enum Action<'a> {
    /// A command that is executed by the integration test, but not
    /// shown in the manual pages.
    Setup(Setup<'a>),

    /// A command that is syntax check (but not run) by the
    /// integration test, and shown in the manual pages.
    SyntaxCheck(Example<'a>),

    /// A command that is executed by the integration test, and shown
    /// in the manual pages.
    Example(Example<'a>),
}

impl<'a> Action<'a> {
    /// Creates a setup action.
    pub const fn setup() -> SetupBuilder<'a> {
        SetupBuilder::new()
    }

    /// Creates an example action.
    pub const fn example() -> ExampleBuilder<'a> {
        ExampleBuilder::new()
    }

    /// Return the action's command, if any.
    #[allow(dead_code)]
    pub fn command(&self) -> Option<&'a [ &'a str ]> {
        match self {
            Action::Setup(Setup { command, .. }) => Some(command),
            Action::SyntaxCheck(Example { command, .. }) => Some(command),
            Action::Example(Example { command, .. }) => Some(command),
        }
    }
}

/// A sequence of actions to execute.
pub struct Actions<'a> {
    pub actions: &'a [Action<'a>],
}

impl<'a> IntoResettable<clap::builder::StyledStr> for Actions<'a> {
    fn into_resettable(self) -> Resettable<clap::builder::StyledStr> {
        // Default width when we aren't connected to a terminal.
        let default_width = 72;

        // We prefix lines with either `# `, `$ `, or `  `.
        const PREFIX_WIDTH: usize = 2;

        let terminal_size = terminal_size::terminal_size();
        let width = if let Some((width, _height)) = terminal_size {
            let width = width.0 as usize;

            if width < 40 {
                // If the terminal is too narrow, then give up and use
                // the default.
                default_width
            } else {
                std::cmp::max(40, width - PREFIX_WIDTH)
            }
        } else {
            default_width
        };

        let mut lines = vec![ "Examples:".to_string() ];

        lines.extend(self.actions
            .iter()
            .filter_map(|action| {
                let example = match action {
                    Action::SyntaxCheck(example) => example,
                    Action::Example(example) => example,

                    // Don't show it.
                    Action::Setup(_) => return None,
                };

                let comment = textwrap::indent(
                    &textwrap::wrap(example.comment, width).join("\n"),
                    "# ");

                // Our manpage generate complains if an
                // example is too long:
                //
                //   warning: Command in example exceeds 64 chars:
                //
                // or
                //
                //   warning: Continuation in example exceeds 57 chars:
                let command = wrap_command(&example.command,
                                           &example.hide,
                                           "", width.min(64),
                                           "  ", width.min(57));

                Some(format!("{}\n{}", comment, command))
            }));

        let text = lines.join("\n\n").into();

        Resettable::Value(text)
    }
}

/// Wraps the given command to width, adding continuation backslashes.
///
/// The first line is prefixed with `indent` and wrapped `to_width`,
/// any continuations are prefixed with `continuation_indent` and
/// wrapped to `continuation_width`.
pub fn wrap_command<S: AsRef<str>>(command: &[S],
                                   hide: &[S],
                                   indent: &str,
                                   to_width: usize,
                                   continuation_indent: &str,
                                   continuation_width: usize)
    -> String
{
    let prompt = platform! {
        unix => { "$" },
        windows => { ">" },
    };

    let mut hide
        = BTreeMap::from_iter(hide.iter().map(|s| (s.as_ref(), false)));

    let result = command
        .iter()
        .filter(|&item| {
            // Remove all of the items in command which are also in
            // hide.
            if let Some(used) = hide.get_mut(item.as_ref()) {
                *used = true;
                // Don't show it.
                false
            } else {
                // Show it.
                true
            }
        })
        .fold(vec![format!("{}{}", indent, prompt)], |mut s, arg| {
            let first = s.len() == 1;

            let arg = arg.as_ref();
            if arg == "|" {
                let last = s.last_mut().expect("have one");
                *last = format!("{} \\", last);
                s.push(format!("  {}", arg));
                return s;
            }

            // Quote the argument, if necessary.
            let quote = |arg: &str| -> String {
                if arg.contains(&[
                    '\"',
                ]) {
                    format!("'{}'", arg)
                } else if arg.chars().any(char::is_whitespace)
                    || arg.contains(&[
                        '`', '#', '$', '&', '*', '(', ')',
                        '\\', '|', '[', ']', '{', '}',
                        ';', '\'', '<', '>', '?', '!',
                    ])
                {
                    format!("\"{}\"", arg)
                } else {
                    arg.to_string()
                }
            };

            // If we have --foo=bar, then only but bar in quotes.
            let mut quoted = None;
            if arg.starts_with("--") {
                if let Some(i) = arg.find('=') {
                    if arg[0..i].chars().all(|c| {
                        c.is_alphanumeric() || c == '-'
                    })
                    {
                        quoted = Some(format!("{}={}",
                                              &arg[..i],
                                              quote(&arg[i + 1..])));
                    }
                }
            }

            let arg = if let Some(quoted) = quoted {
                quoted
            } else {
                quote(arg)
            };

            let last = s.last_mut().expect("have one");

            let last_chars = last.chars().count();
            let arg_chars = arg.chars().count();

            let max_width = if first { to_width } else { continuation_width };
            if last_chars + 1 + arg_chars <= max_width {
                *last = format!("{} {}", last, arg);
            } else {
                *last = format!("{} \\", last);
                s.push(format!("{}{}", continuation_indent, arg));
            }

            s
        })
        .join("\n");

    #[cfg(debug_assertions)]
    for (arg, used) in hide.into_iter() {
        if ! used {
            panic!("Example `{}` includes an argument to hide (`{}`), but the \
                    argument wasn't used by the example!",
                   command.iter()
                       .map(|arg| arg.as_ref().to_string())
                       .collect::<Vec<String>>()
                       .join(" "),
                   arg);
        }
    }

    result
}

macro_rules! test_examples {
    ($ident:ident, $actions:expr) => {
        #[test]
        fn $ident() {
            use std::path::PathBuf;

            use tempfile::TempDir;
            use assert_cmd::Command;


            let fixtures = PathBuf::from(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/data/examples"));

            let tmp_dir = TempDir::new().unwrap();

            let options = fs_extra::dir::CopyOptions::new()
                .content_only(true);
            fs_extra::dir::copy(&fixtures, &tmp_dir, &options)
                .expect(&format!("Copying {:?} to {:?}",
                                 fixtures, &tmp_dir));

            // Create an empty policy configuration file.  We use this
            // instead of the system-wide policy configuration file,
            // which might be more strict than what our test vectors
            // expect.
            let policy = tmp_dir.path().join("empty-policy.toml");
            std::fs::write(&policy, "").unwrap();

            let home = tmp_dir.path().join("home");
            let cert_store = tmp_dir.path().join("cert-store");
            let key_store = tmp_dir.path().join("key-store");

            eprintln!("Testing example from {}:{}", file!(), line!());

            for (i, action) in $actions.actions.into_iter().enumerate() {
                let command = if let Some(command) = action.command() {
                    command
                } else {
                    continue;
                };

                if let Action::SyntaxCheck(_) = &action {
                    // Just syntax check it.
                    eprintln!("Syntax checking: {:?}", command);

                    use clap::Parser;
                    if let Err(err) = $crate::cli::SqCommand::try_parse_from(command.iter()) {
                        eprintln!("example:{}:{}: checking example #{}: {}",
                                  file!(), line!(), i + 1, err);
                        panic!("syntax checking example failed");
                    }

                    continue;
                }

                // Handle pipelines by tracking intermediate results.
                let mut intermediate = None;
                for command in command.split(|p| *p == "|") {
                    eprintln!("Executing: {:?}", command);

                    let mut cmd = Command::cargo_bin(command[0]).unwrap();
                    cmd.current_dir(&tmp_dir)
                        .env("RUST_BACKTRACE", "1")
                        .env("RUST_LOG", "trace")
                        .env("SEQUOIA_CRYPTO_POLICY", &policy)
                        .env("SEQUOIA_HOME", &home)
                        .env("SEQUOIA_CERT_STORE", &cert_store)
                        .env("SEQUOIA_KEY_STORE", &key_store)
                        .arg("--batch")
                        .args(&command[1..]);

                    if let Some(prev) = intermediate {
                        cmd.write_stdin(prev);
                    }

                    let res = cmd.assert();
                    intermediate = Some(res.get_output().stdout.clone());
                    if let Err(err) = res.try_success() {
                        eprintln!("example:{}:{}: executing example #{}: {}",
                                  file!(), line!(), i + 1, err);
                        panic!("executing example failed");
                    }
                }
            }
        }
    };
}
