//! Command-line parser for `sq config inspect policy`.

use clap::Args;

use crate::cli::examples::*;

#[derive(Debug, Args)]
#[clap(
    name = "policy",
    about = "Inspect the cryptographic policy",
    long_about = "\
Inspect the cryptographic policy

Explains the cryptographic policy that Sequoia uses to \
either accept or reject algorithms and packets outright, \
or at a configured point in time.
",
    after_help = EXAMPLES,
)]
pub struct Command {
}

const EXAMPLES: Actions = Actions {
    actions: &[
        Action::example()
            .comment("Inspect the cryptographic policy.")
            .command(&[
                "sq", "config", "inspect", "policy",
            ])
            .build(),
    ],
};
test_examples!(sq_config_inspect_policy, EXAMPLES);
