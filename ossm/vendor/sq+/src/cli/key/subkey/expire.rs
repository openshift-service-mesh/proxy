use clap::Args;

use crate::cli::examples;
use examples::Action;
use examples::Actions;

use crate::cli::types::CertDesignators;
use crate::cli::types::ClapData;
use crate::cli::types::ExpirationArg;
use crate::cli::types::FileOrStdout;
use crate::cli::types::KeyDesignators;
use crate::cli::types::cert_designator;

pub struct AdditionalDocs {}

impl cert_designator::AdditionalDocs for AdditionalDocs {
    fn help(arg: &'static str, help: &'static str) -> clap::builder::StyledStr {
        match arg {
            "file" =>
                "Change the expiration of the specified (sub)keys on the key \
                 read from PATH"
                .into(),
            _ => {
                debug_assert!(help.starts_with("Use certificates"));
                help.replace("Use certificates",
                             "Change the expiration of the specified (sub)keys \
                              on the key")
                    .into()
            },
        }
    }
}

#[derive(Debug, Args)]
#[clap(
    name = "expire",
    about = "Change a subkey's expiration time",
    long_about = "\
Change a subkey's expiration time

This subcommand changes a key's expiration time.  To change the \
expiration time of the certificate, use the `sq key expire` \
subcommand.

Changing the expiration time of the primary key is equivalent to \
changing the certificate's expiration time.  The expiration time \
of a subkey is bound by the expiration of the certificate.
",
    after_help = EXAMPLES,
)]
#[clap(mut_arg("expiration", |arg| {
    arg.required(true)
}))]
pub struct Command {
    #[command(flatten)]
    pub cert: CertDesignators<
        cert_designator::CertUserIDEmailFileArgs,
        cert_designator::CertPrefix,
        cert_designator::OneValueAndFileRequiresOutput,
        AdditionalDocs>,

    #[command(flatten)]
    pub keys: KeyDesignators,

    #[command(flatten)]
    pub expiration: ExpirationArg,

    #[clap(
        long,
        value_name = FileOrStdout::VALUE_NAME,
        help = "Write to the specified FILE",
        long_help = "\
Write to the specified FILE

If not specified, and the certificate was read from the certificate \
store, imports the modified certificate into the cert store.  If not \
specified, and the certificate was read from a file, writes the \
modified certificate to stdout.",
    )]
    pub output: Option<FileOrStdout>,
}

const EXAMPLES: Actions = Actions {
    actions: &[
        Action::setup().command(&[
            "sq", "key", "import", "alice-secret.pgp"
        ]).build(),

        Action::example().comment("\
Change Alice's authentication subkey to expire in 6 months."
        ).command(&[
            "sq", "key", "subkey", "expire", "--expiration", "6m",
            "--cert=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            "--key=0D45C6A756A038670FDFD85CB1C82E8D27DB23A1",
        ]).build(),
    ],
};
test_examples!(sq_key_subkey_expire, EXAMPLES);
