//! Command-line parser for `sq encrypt`.

use clap::{ValueEnum, Parser};

use super::types::ClapData;
use super::types::EncryptPurpose;
use super::types::FileOrStdin;
use super::types::FileOrStdout;

use crate::cli::config;
use crate::cli::types::CertDesignators;
use crate::cli::types::cert_designator::*;
use crate::cli::types::Profile;

use crate::cli::examples;
use examples::*;

/// Key for the help augmentation.
pub const ENCRYPT_FOR_SELF: &str = "encrypt.for-self";

const ENCRYPT_EXAMPLES: Actions = Actions {
    actions: &[
        Action::setup().command(&[
            "sq", "pki", "link", "add",
            "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            "--email", "alice@example.org",
        ]).build(),

        Action::setup().command(&[
            "sq", "key", "import", "juliet-secret.pgp",
        ]).build(),

        Action::setup().command(&[
            "sq", "pki", "link", "add",
            "--cert=7A58B15E3B9459483D9FFA8D40E299AC5F2B0872",
            "--email=juliet@example.org",
        ]).build(),

        Action::example().comment(
            "Encrypt a file for a recipient given by fingerprint.",
        ).command(&[
            "sq", "encrypt",
            "--for=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            "--signer-email=juliet@example.org",
            "document.txt",
        ]).build(),

        Action::example().comment(
            "Encrypt a file for a recipient given by email.",
        ).command(&[
            "sq", "encrypt",
            "--for-email=alice@example.org",
            "--signer-email=juliet@example.org",
            "document.txt",
        ]).build(),
    ]
};

test_examples!(sq_encrypt, ENCRYPT_EXAMPLES);

#[derive(Parser, Debug)]
#[clap(
    name = "encrypt",
    about = "Encrypt a message",
    long_about =
"Encrypt a message

Encrypt a message for any number of recipients and with any number of \
passwords, optionally signing the message in the process.

The converse operation is `sq decrypt`.

`sq encrypt` respects the reference time set by the top-level \
`--time` argument.  It uses the reference time when selecting \
encryption keys, and it sets the signature's creation time to the \
reference time.
",
    after_help = ENCRYPT_EXAMPLES,
)]
pub struct Command {
    #[clap(
        default_value_t = FileOrStdin::default(),
        help = FileOrStdin::HELP_OPTIONAL,
        value_name = FileOrStdin::VALUE_NAME,
    )]
    pub input: FileOrStdin,
    #[clap(
        default_value_t = FileOrStdout::default(),
        help = FileOrStdout::HELP_OPTIONAL,
        long,
        value_name = FileOrStdout::VALUE_NAME,
    )]
    pub output: FileOrStdout,
    #[clap(
        long,
        help = "Emit binary data",
    )]
    pub binary: bool,

    #[command(flatten)]
    pub recipients: CertDesignators<CertUserIDEmailFileSelfWithPasswordArgs,
                                    RecipientPrefix>,

    #[clap(
        help = "Set the filename of the encrypted file as metadata",
        long = "set-metadata-filename",
        long_help =
            "Set the filename of the encrypted file as metadata

Do note, that this metadata is not signed and as such relying on \
it - on sender or receiver side - is generally considered \
dangerous.",
    )]
    pub set_metadata_filename: Option<String>,

    #[command(flatten)]
    pub signers: CertDesignators<CertUserIDEmailFileSelfArgs,
                                 SignerPrefix,
                                 SignerOrWithoutSignature,
                                 SignerDoc>,


    #[command(flatten)]
    pub signature_notations: crate::cli::types::SignatureNotationsArg,

    #[clap(
        long = "encrypt-for",
        value_name = "PURPOSE",
        default_value_t = EncryptPurpose::Universal,
        help = "Select what kind of keys are considered for encryption",
        value_enum,
    )]
    pub mode: EncryptPurpose,

    #[clap(
        long = "compression",
        value_name = "KIND",
        default_value_t = CompressionMode::Pad,
        help = "Select compression scheme to use",
        value_enum,
    )]
    pub compression: CompressionMode,
    #[clap(
        long = "use-expired-subkey",
        help = "Fall back to expired encryption subkeys",
        long_help = "Fall back to expired encryption subkeys

If a certificate has only expired \
encryption-capable subkeys, fall back \
to using the one that expired last",
    )]
    pub use_expired_subkey: bool,

    #[clap(
        long = "profile",
        value_name = "PROFILE",
        default_value_t = Default::default(),
        help = "Select the default OpenPGP standard for the encryption container",
        long_help = config::augment_help(
            "key.generate.profile",
            "Select the default OpenPGP standard for the encryption container

When encrypting for certificates, the encryption container is selected \
based on the stated preferences of the recipients.  However, if there \
is no guidance, for example because the message is encrypted only with \
passwords, sq falls back to this profile.

As OpenPGP evolves, new versions will become available.  This option \
selects the version of OpenPGP to use for encrypting messages if the \
version can not be inferred otherwise.

Currently, sq supports two profiles: RFC9580 and RFC4880.  Currently, \
the default is RFC4880.  However, once support for RFC9580 is rolled \
out further, the default will change in a future version of sq."),
        value_enum,
    )]
    pub profile: Profile,

    /// Workaround for https://github.com/clap-rs/clap/issues/3846
    #[clap(skip)]
    pub profile_source: Option<clap::parser::ValueSource>,
}

/// Documentation for signer arguments.
pub struct SignerDoc {}
impl AdditionalDocs for SignerDoc {
    fn help(arg: &'static str, help: &'static str) -> clap::builder::StyledStr {
        match arg {
            "file" =>
                "Sign the message using the key read from PATH"
                .into(),
            _ => {
                debug_assert!(help.starts_with("Use certificates"));
                help.replace("Use certificates",
                             "Sign the message using the key")
                    .into()
            },
        }
    }
}

#[derive(ValueEnum, Debug, Clone)]
pub enum CompressionMode {
    None,
    Pad,
    Zip,
    Zlib,
    Bzip2
}
