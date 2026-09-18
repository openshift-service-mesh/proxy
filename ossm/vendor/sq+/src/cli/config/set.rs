//! Command-line parser for `sq config`.

use clap::Args;

use crate::cli::examples::*;

// XXX: We don't currently expose the set command.
#[derive(Debug, Args)]
#[clap(
    name = "set",
    about = "Set configuration options",
    long_about = "\
Set configuration options

Changes the configuration with the given key.  Use `sq config get` \
to see all existing options and their values.
",
    after_help = SET_EXAMPLES,
)]
// XXX: value and delete should be in an argument group, but doing
// that messes up the usage:
//
//   Usage: sq config set <VALUE|--delete> <NAME>
//
// Note how VALUE comes first.  I believe this is tracked upstream as
// https://github.com/clap-rs/clap/issues/1794
//
// For now, we do the validation in the command handler.
//
//#[clap(group(ArgGroup::new("action").args(&["value", "delete"]).required(true)))]
pub struct Command {
    #[clap(
        value_name = "NAME",
        help = "Set the value of the configuration NAME",
    )]
    pub name: String,

    #[clap(
        value_name = "VALUE",
        help = "New value for the configuration item",
    )]
    pub value: Option<String>,

    #[clap(
        long = "delete",
        help = "Delete the configuration item",
        conflicts_with = "value",
    )]
    pub delete: bool,

    #[clap(
        long = "add",
        help = "Add an item to a list of items",
        conflicts_with = "delete",
    )]
    pub add: bool,
}

const SET_EXAMPLES: Actions = Actions {
    actions: &[
        Action::Example(Example {
            comment: "\
Set the default cipher suite for key generation.",
            command: &[
                "sq", "config", "set", "key.generate.cipher-suite",
                "rsa3k",
            ],
            hide: &[],
        }),

        Action::Example(Example {
            comment: "\
Delete the default cipher suite for key generation.",
            command: &[
                "sq", "config", "set", "key.generate.cipher-suite",
                "--delete",
            ],
            hide: &[],
        }),

        Action::Example(Example {
            comment: "\
Add a default key server for network queries.",
            command: &[
                "sq", "config", "set", "network.keyservers",
                "--add", "hkps://keys.example.org",
            ],
            hide: &[],
        }),
    ]
};
// XXX: We don't currently expose the set command.
//test_examples!(sq_config_set, SET_EXAMPLES);
