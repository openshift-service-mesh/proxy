//! Command-line parser for `sq config inspect network`.

use clap::Args;

use crate::cli::examples::*;

#[derive(Debug, Args)]
#[clap(
    name = "network",
    about = "Inspect the network configuration",
    long_about = "\
Inspect the network configuration

Prints the network configuration.  This can be used to gauge the \
metadata leakage resulting from network operations.
",
    after_help = EXAMPLES,
)]
pub struct Command {
}

const EXAMPLES: Actions = Actions {
    actions: &[
        Action::example()
            .comment("Inspect the network configuration.")
            .command(&[
                "sq", "config", "inspect", "network",
            ])
            .build(),
    ],
};
test_examples!(sq_config_inspect_network, EXAMPLES);
