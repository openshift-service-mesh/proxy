//! Command-line parser for `sq config inspect paths`.

use clap::Args;

use crate::cli::examples::*;

#[derive(Debug, Args)]
#[clap(
    name = "paths",
    about = "Inspect relevant paths",
    long_about = "\
Inspect relevant paths

Prints paths that are used by sq, such as the location of the home \
directory, the configuration file, the certificate store, the key \
store, etc. \
",
    after_help = EXAMPLES,
)]
pub struct Command {
}

const EXAMPLES: Actions = Actions {
    actions: &[
        Action::example()
            .comment("Inspect relevant paths.")
            .command(&[
                "sq", "config", "inspect", "paths",
            ])
            .build(),
    ],
};
test_examples!(sq_config_inspect_paths, EXAMPLES);
