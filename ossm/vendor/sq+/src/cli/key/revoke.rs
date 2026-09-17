//! Command-line parser for `sq key revoke`.

use clap::Args;

use crate::cli::types::ClapData;
use crate::cli::types::FileOrStdout;

use crate::cli::examples::*;
use crate::cli::key::KeyReasonForRevocation;
use crate::cli::types::cert_designator::*;

const REVOKE_EXAMPLES: Actions = Actions {
    actions: &[
        Action::setup().command(&[
            "sq", "key", "import", "alice-secret.pgp"
        ]).build(),

        Action::example().comment("\
Revoke Alice's key, indicating that there is a new certificate."
        ).command(&[
            "sq", "key", "revoke",
            "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            "--reason", "superseded",
            "--message", "My new cert is C5999E8191BF7B503653BE958B1F7910D01F86E5",
        ]).build(),

        Action::example().comment("\
Revoke the key, indicating that the secret key material was \
compromised."
        ).command(&[
            "sq", "key", "revoke",
            "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            "--reason", "compromised",
            "--message", "Computer attacked, secret key material compromised",
        ]).build(),
    ]
};
test_examples!(sq_key_revoke, REVOKE_EXAMPLES);

#[derive(Debug, Args)]
#[clap(
    about = "Revoke a certificate",
    long_about = "\
Revoke a certificate

Creates a revocation certificate for a certificate.

If `--revoker` or `--revoker-file` is provided, then that key is used \
to create the revocation certificate.  If that key is different from \
the certificate that is being revoked, this results in a third-party \
revocation.  This is normally only useful if the owner of the \
certificate designated the key to be a designated revoker.

`sq key revoke` respects the reference time set by the top-level \
`--time` argument.  When set, it uses the specified time instead of \
the current time when determining what keys are valid, and it sets \
the revocation certificate's creation time to the reference time \
instead of the current time.
",
    after_help = REVOKE_EXAMPLES,
)]
pub struct Command {
    #[command(flatten)]
    pub cert: CertDesignators<CertUserIDEmailFileArgs,
                              CertPrefix,
                              OneValueAndFileRequiresOutput,
                              KeyRevokeCertDoc>,

    #[command(flatten)]
    pub revoker: CertDesignators<CertUserIDEmailFileArgs,
                                 RevokerPrefix,
                                 OneOptionalValue,
                                 KeyRevokeRevokerDoc>,

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
of the certificate.",
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
explains why the certificate has been revoked.  For instance, if Alice \
has created a new key, she would generate a `superseded` revocation \
certificate for her old key, and might include the message `I've \
created a new certificate, $FINGERPRINT, please use that in the \
future.`",
    )]
    pub message: String,

    #[command(flatten)]
    pub signature_notations: crate::cli::types::SignatureNotationsArg,

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

/// Documentation for the cert designators for the key revoke.
pub struct KeyRevokeCertDoc {}

impl AdditionalDocs for KeyRevokeCertDoc {
    fn help(arg: &'static str, help: &'static str) -> clap::builder::StyledStr {
        match arg {
            "file" =>
                "Revoke the key read from PATH"
                .into(),
            _ => {
                debug_assert!(help.starts_with("Use certificates"));
                help.replace("Use certificates",
                             "Revoke the key")
            },
        }.into()
    }
}

/// Documentation for the revoker designators for the key revoke.
pub struct KeyRevokeRevokerDoc {}

impl AdditionalDocs for KeyRevokeRevokerDoc {
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
