//! Command-line parser for `sq key delete`.

use clap::Args;

use crate::cli::types::*;
use crate::cli::examples::*;
use crate::cli::types::cert_designator::*;

#[derive(Debug, Args)]
#[clap(
    name = "delete",
    about = "Delete a certificate's secret key material",
    after_help = EXAMPLES,
)]
pub struct Command {
    #[command(flatten)]
    pub cert: CertDesignators<CertUserIDEmailFileArgs,
                              CertPrefix,
                              OneValueAndFileRequiresOutput,
                              DeleteKeyDoc>,

    #[clap(
        long,
        value_name = FileOrStdout::VALUE_NAME,
        conflicts_with = "cert",
        help = "Write the stripped certificate to the specified file",
    )]
    pub output: Option<FileOrStdout>,
}

const EXAMPLES: Actions = Actions {
    actions: &[
        Action::setup().command(&[
            "sq", "key", "import", "alice-secret.pgp",
        ]).build(),

        Action::example().comment("\
Delete any secret key associated with Alice's certificate."
        ).command(&[
            "sq", "key", "delete",
            "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
        ]).build(),

        Action::setup().command(&[
            "sq", "key", "import", "alice-secret.pgp",
        ]).build(),

        Action::setup().command(&[
            "sq", "pki", "link", "add",
            "--cert=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            "--userid=Alice <alice@example.org>",
        ]).build(),

        Action::example().comment("\
Delete any secret key associated with Alice's certificate \
selected by user ID."
        ).command(&[
            "sq", "key", "delete",
            "--cert-email=alice@example.org",
        ]).build(),
    ]
};
test_examples!(sq_key_delete, EXAMPLES);

/// Documentation for the cert designators for the key delete.
pub struct DeleteKeyDoc {}

impl AdditionalDocs for DeleteKeyDoc {
    fn help(arg: &'static str, help: &'static str) -> clap::builder::StyledStr {
        match arg {
            "file" =>
                "Delete the secret key material from the key read from PATH"
                .into(),
            _ => {
                debug_assert!(help.starts_with("Use certificates"));
                help.replace("Use certificates",
                             "Delete secret key material from the key")
            },
        }.into()
    }
}
