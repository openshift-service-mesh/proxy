//! Command-line parser for `sq key import`.

use std::path::PathBuf;

use clap::Args;

use crate::cli::examples::*;

#[derive(Debug, Args)]
#[clap(
    about = "Import keys into the key store",
    after_help = IMPORT_EXAMPLES,
)]
pub struct Command {
    #[clap(
        value_name = "KEY_FILE",
        help = "Read from KEY_FILE or stdin if omitted",
    )]
    pub input: Vec<PathBuf>,
}

const IMPORT_EXAMPLES: Actions = Actions {
    actions: &[
        Action::example().comment("\
Import the keys into the key store."
        ).command(&[
            "sq", "key", "import", "alice-secret.pgp",
        ]).build(),
    ]
};
test_examples!(sq_key_import, IMPORT_EXAMPLES);
