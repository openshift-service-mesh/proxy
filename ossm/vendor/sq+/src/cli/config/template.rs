//! Command-line parser for `sq config template`.

use clap::Args;

use crate::cli::{
    examples::*,
    types::{ClapData, FileOrStdout},
};

#[derive(Debug, Args)]
#[clap(
    name = "template",
    about = "Write a template configuration file",
    long_about = "\
Write a template configuration file

Writes a template containing the default values to the given file or stdout.  \
This can be used as a starting point to tweak the configuration.",
    after_help = TEMPLATE_EXAMPLES,
)]
pub struct Command {
    #[clap(
        long,
        value_name = FileOrStdout::VALUE_NAME,
        default_value_t = FileOrStdout::default(),
        help = FileOrStdout::HELP_OPTIONAL,
    )]
    pub output: FileOrStdout,
}

const TEMPLATE_EXAMPLES: Actions = Actions {
    actions: &[
        Action::Example(Example {
            comment: "\
Write a template configuration.",
            command: &[
                "sq", "config", "template",
            ],
            hide: &[],
        }),
    ]
};
test_examples!(sq_config_template, TEMPLATE_EXAMPLES);
