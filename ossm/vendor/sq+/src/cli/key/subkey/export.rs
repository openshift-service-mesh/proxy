use clap::Args;

use crate::cli::examples;
use examples::Action;
use examples::Actions;

use crate::cli::types::CertDesignators;
use crate::cli::types::ClapData;
use crate::cli::types::FileOrStdout;
use crate::cli::types::KeyDesignators;
use crate::cli::types::cert_designator;
use crate::cli::types::key_designator;

pub struct AdditionalDocs {}

impl key_designator::AdditionalDocs for AdditionalDocs {
    fn help(_arg: &'static str, _help: &'static str) -> clap::builder::StyledStr {
        "Export the secret key material for the specified primary key \
         or subkey".into()
    }
}

#[derive(Debug, Args)]
#[clap(
    about = "Export secret key material from the secret key store",
    long_about = "\
Export secret key material from the secret key store

Exports the secret key material.  Note that even if secret key \
material is available, it may not be exportable.  For instance, secret \
key material stored on a hardware security module usually cannot be \
exported from the device.

The entire certificate is exported, but only the specified key's \
secret key material is exported.  An error is returned if the secret \
key material for the specified key is not available.

If you want to export all secret key material associated with a \
certificate, use `sq key export`.
",
    after_help = EXAMPLES,
)]
pub struct Command {
    #[command(flatten)]
    pub cert: CertDesignators<
        cert_designator::CertUserIDEmailArgs,
        cert_designator::CertPrefix,
        cert_designator::OneValue>,

    #[command(flatten)]
    pub keys: KeyDesignators<
        key_designator::DefaultOptions,
        AdditionalDocs>,

    #[clap(
        default_value_t = FileOrStdout::default(),
        help = FileOrStdout::HELP_OPTIONAL,
        long,
        value_name = FileOrStdout::VALUE_NAME,
    )]
    pub output: FileOrStdout,
}

const EXAMPLES: Actions = Actions {
    actions: &[
        Action::setup().command(&[
            "sq", "key", "import", "alice-secret.pgp"
        ]).build(),

        Action::example().comment("\
Export Alice's signing-capable and encryption-capable subkeys, but not \
her primary key or her authentication-capable subkey."
        ).command(&[
            "sq", "key", "subkey", "export",
            "--cert=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            "--key=42020B87D51877E5AF8D272124F3955B0B8DECC8",
            "--key=74DCDEAF17D9B995679EB52BA6E65EA2C8497728",
        ]).build(),
    ]
};
test_examples!(sq_subkey_key_export, EXAMPLES);
