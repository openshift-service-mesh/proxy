use clap::Args;

use crate::cli::examples;
use examples::Action;
use examples::Actions;

use crate::cli::key::KeyReasonForRevocation;
use crate::cli::types::CertDesignators;
use crate::cli::types::ClapData;
use crate::cli::types::FileOrCertStore;
use crate::cli::types::FileOrStdout;
use crate::cli::types::KeyDesignators;
use crate::cli::types::cert_designator;
use crate::cli::types::key_designator;

/// Documentation for the cert designators for the cert argument of
/// the key subkey revoke command.
pub struct CertDoc {}

impl cert_designator::AdditionalDocs for CertDoc {
    fn help(arg: &'static str, help: &'static str) -> clap::builder::StyledStr {
        match arg {
            "file" =>
                "Revoke the specified subkeys on the key read from PATH"
                .into(),
            _ => {
                debug_assert!(help.starts_with("Use certificates"));
                help.replace("Use certificates",
                             "Revoke the specified subkeys on the key")
                    .into()
            },
        }
    }
}

/// Documentation for the revoker designators for revoker argument of
/// the key subkey revoke command .
pub struct RevokerDoc {}

impl cert_designator::AdditionalDocs for RevokerDoc {
    fn help(_: &'static str, help: &'static str) -> clap::builder::StyledStr {
        format!("{} to create the revocation certificate",
                help.replace("certificates", "key")).into()
    }

    fn long_help(_: &'static str, help: &'static str) -> Option<clap::builder::StyledStr> {
        Some(format!("{} to create the revocation certificate

Sign the revocation certificate using the specified key.  By default, \
the certificate being revoked is used.  Using this option, it is \
possible to create a third-party revocation.",
                     help.replace("certificates", "key")).into())
    }
}

pub struct KeyAdditionalDocs {}

impl key_designator::AdditionalDocs for KeyAdditionalDocs {
    fn help(_arg: &'static str, _help: &'static str)
        -> clap::builder::StyledStr
    {
        "Revoke the specified subkey".into()
    }
}

#[derive(Debug, Args)]
#[clap(
    about = "Revoke a subkey",
    long_about =
"Revoke a subkey

Creates a revocation certificate for a subkey.

If `--revoker` or `--revoker-file` is provided, then that key is used \
to create the revocation certificate.  If that key is different from \
the certificate that is being revoked, this results in a third-party \
revocation.  This is normally only useful if the owner of the \
certificate designated the key to be a designated revoker.

`sq key subkey revoke` respects the reference time set by the top-level \
`--time` argument.  When set, it uses the specified time instead of \
the current time when determining what keys are valid, and it sets \
the revocation certificate's creation time to the reference time \
instead of the current time.
",
    after_help = EXAMPLES,
)]
pub struct Command {
    #[command(flatten)]
    pub cert: CertDesignators<
        cert_designator::CertUserIDEmailFileArgs,
        cert_designator::CertPrefix,
        cert_designator::OneValueAndFileRequiresOutput,
        CertDoc>,

    #[command(flatten)]
    pub revoker: CertDesignators<
        cert_designator::CertUserIDEmailFileArgs,
        cert_designator::RevokerPrefix,
        cert_designator::OneOptionalValue,
        RevokerDoc>,

    #[command(flatten)]
    pub keys: KeyDesignators<
        key_designator::OnlySubkeys,
        KeyAdditionalDocs>,

    #[clap(
        long,
        value_name = "REASON",
        required = true,
        help = "The reason for the revocation",
        long_help = "\
The reason for the revocation

If the reason happened in the past, you should specify that using the \
`--time` argument.  This allows OpenPGP implementations to more \
accurately reason about artifacts whose validity depends on the validity \
of the user ID.",
        value_enum,
    )]
    pub reason: KeyReasonForRevocation,

    #[clap(
        long,
        value_name = "MESSAGE",
        required = true,
        help = "A short, explanatory text",
        long_help = "\
A short, explanatory text

The text is shown to a viewer of the revocation certificate, and \
explains why the subkey has been revoked.  For instance, if Alice has \
created a new key, she would generate a `superseded` revocation \
certificate for her old key, and might include the message \"I've \
created a new subkey, please refresh the certificate.\"",
    )]
    pub message: String,

    #[command(flatten)]
    pub signature_notations: crate::cli::types::SignatureNotationsArg,

    #[clap(
        long,
        value_name = FileOrCertStore::VALUE_NAME,
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
Revoke Alice's signing subkey."
        ).command(&[
            "sq", "key", "subkey", "revoke",
            "--cert=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            "--key=42020B87D51877E5AF8D272124F3955B0B8DECC8",
            "--reason", "retired",
            "--message", "Subkey rotation.",
        ]).build(),

        Action::example().comment("\
Revoke Alice's signing subkey and encryption subkeys."
        ).command(&[
            "sq", "key", "subkey", "revoke",
            "--cert=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            "--key=42020B87D51877E5AF8D272124F3955B0B8DECC8",
            "--key=74DCDEAF17D9B995679EB52BA6E65EA2C8497728",
            "--reason", "retired",
            "--message", "Subkey rotation.",
        ]).build(),
    ],
};
test_examples!(sq_key_subkey_revoke, EXAMPLES);
