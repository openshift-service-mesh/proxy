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

pub struct CertAdditionalDocs {}

impl cert_designator::AdditionalDocs for CertAdditionalDocs {
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

pub struct KeyAdditionalDocs {}

impl key_designator::AdditionalDocs for KeyAdditionalDocs {
    fn help(_arg: &'static str, _help: &'static str)
        -> clap::builder::StyledStr
    {
        "Delete the specified key's secret key material".into()
    }
}

#[derive(Debug, Args)]
#[clap(
    name = "delete",
    about = "Delete a certificate's secret key material",
    long_about = "\
Delete a certificate's secret key material

Unlike `sq key delete`, which deletes all the secret key material, this \
command only deletes the specified secret key material.

If the secret key material is managed by multiple devices, it is \
deleted from all of them.

Although the secret key material is deleted, the public keys are \
retained.  If you don't want the keys to be used anymore you should \
revoke the keys using `sq key subkey revoke`.
",
    after_help = EXAMPLES,
)]
pub struct Command {
    #[command(flatten)]
    pub cert: CertDesignators<
        cert_designator::CertUserIDEmailFileArgs,
        cert_designator::CertPrefix,
        cert_designator::OneValueAndFileRequiresOutput,
        CertAdditionalDocs>,

    #[command(flatten)]
    pub keys: KeyDesignators<
        key_designator::DefaultOptions,
        KeyAdditionalDocs>,

    #[clap(
        long,
        value_name = FileOrStdout::VALUE_NAME,
        conflicts_with = "cert",
        help = "Write the stripped certificate to the specified file",
        long_help = "\
Write the stripped certificate to the specified file

This option only makes sense when deleting the secret key material from a \
file.  When deleting secret key material managed by the key store using \
`--cert`, you can get the stripped certificate using `sq key export`.",
    )]
    pub output: Option<FileOrStdout>,
}

const EXAMPLES: Actions = Actions {
    actions: &[
        Action::setup().command(&[
            "sq", "key", "import", "alice-secret.pgp"
        ]).build(),

        Action::example().comment("\
Delete Alice's signing subkey."
        ).command(&[
            "sq", "key", "subkey", "delete",
            "--cert=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            "--key=42020B87D51877E5AF8D272124F3955B0B8DECC8",
        ]).build(),
    ]
};
test_examples!(sq_key_subkey_delete, EXAMPLES);
