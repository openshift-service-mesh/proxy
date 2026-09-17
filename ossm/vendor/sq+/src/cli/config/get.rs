//! Command-line parser for `sq config get`.

use clap::Args;

use crate::cli::examples::*;

#[derive(Debug, Args)]
#[clap(
    name = "get",
    about = "Get configuration options",
    long_about = "\
Get configuration options

Retrieves the configuration with the given key.  Use `sq config get` \
to see all available options and their values.",
    after_help = GET_EXAMPLES,
)]
pub struct Command {
    #[clap(
        value_name = "NAME",
        help = "Get the value of the configuration NAME",
    )]
    pub name: Option<String>,
}

const GET_EXAMPLES: Actions = Actions {
    actions: &[
        Action::Example(Example {
            comment: "\
List all configuration options.",
            command: &[
                "sq", "config", "get",
            ],
            hide: &[],
        }),

        Action::Example(Example {
            comment: "\
Get the default cipher suite for key generation.",
            command: &[
                "sq", "config", "get", "key.generate.cipher-suite",
            ],
            hide: &[],
        }),
    ]
};
test_examples!(sq_config_get, GET_EXAMPLES);
