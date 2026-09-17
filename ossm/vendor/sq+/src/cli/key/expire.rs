//! Command-line parser for `sq key expire`.

use clap::Args;

use crate::cli::types::ClapData;
use crate::cli::types::ExpirationArg;
use crate::cli::types::FileOrStdout;

use crate::cli::examples::*;
use crate::cli::types::cert_designator::*;

const EXAMPLES: Actions = Actions {
    actions: &[
        Action::setup().command(&[
            "sq", "key", "import",
            "alice-secret.pgp",
        ]).build(),

        Action::example().comment(
            "Change Alice's certificate to expire in a year."
        ).command(&[
            "sq", "key", "expire", "--expiration", "1y",
            "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
        ]).build(),

        Action::example().comment(
            "Change Alice's certificate to never expire."
        ).command(&[
            "sq", "key", "expire", "--expiration", "never",
            "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
        ]).build(),
    ],
};

test_examples!(sq_key_expire, EXAMPLES);

#[derive(Debug, Args)]
#[clap(
    name = "expire",
    about = "Change a certificate's expiration time",
    long_about =
"Change a certificate's expiration time

This subcommand changes a certificate's expiration time.  To change \
the expiration time of an individual subkey, use the `sq key subkey \
expire` subcommand.
",
    after_help = EXAMPLES,
)]
#[clap(mut_arg("expiration", |arg| {
    arg.required(true)
}))]
pub struct Command {
    #[command(flatten)]
    pub cert: CertDesignators<CertUserIDEmailFileArgs,
                              CertPrefix,
                              OneValueAndFileRequiresOutput,
                              KeyExpireDoc>,

    #[clap(
        help = FileOrStdout::HELP_OPTIONAL,
        long,
        value_name = FileOrStdout::VALUE_NAME,
    )]
    pub output: Option<FileOrStdout>,

    #[clap(flatten)]
    pub expiration: ExpirationArg,
}

/// Documentation for the cert designators for the key expire.
pub struct KeyExpireDoc {}

impl AdditionalDocs for KeyExpireDoc {
    fn help(arg: &'static str, help: &'static str) -> clap::builder::StyledStr {
        match arg {
            "file" =>
                "Change the expiration of the key \
                 read from PATH"
                .into(),
            _ => {
                debug_assert!(help.starts_with("Use certificates"));
                help.replace("Use certificates",
                             "Change the expiration of the key")
            },
        }.into()
    }
}
