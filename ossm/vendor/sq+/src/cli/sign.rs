//! Command-line parser for `sq sign`.

use std::path::PathBuf;

use clap::{ArgGroup, Parser, ValueEnum};

use sequoia_openpgp::{
    types::SignatureType,
};

use super::types::ClapData;
use super::types::FileOrStdin;
use super::types::FileOrStdout;

use crate::cli::examples;
use examples::*;
use crate::cli::types::cert_designator::*;

/// Key for the help augmentation.
pub const SIGNER_SELF: &str = "sign.signer-self";

const SIGN_EXAMPLES: Actions = Actions {
    actions: &[
        Action::example().comment(
            "Create a signed message.",
        ).command(&[
            "sq", "sign", "--signer-file", "juliet-secret.pgp",
            "--message",
            "document.txt",
        ]).build(),

        Action::example().comment(
            "Create a detached signature.",
        ).command(&[
            "sq", "sign", "--signer-file", "juliet-secret.pgp",
            "--signature-file=document.txt.sig", "document.txt",
        ]).build(),
    ],
};
test_examples!(sq_sign, SIGN_EXAMPLES);

#[derive(Parser, Debug)]
#[clap(
    name = "sign",
    about = "Sign messages or data files",
    long_about =
"Sign messages or data files

Creates signed messages or detached signatures.  Detached signatures \
are often used to sign software packages.

The converse operation is `sq verify`.

`sq sign` respects the reference time set by the top-level \
`--time` argument.  When set, it uses the specified time instead of \
the current time, when determining what keys are valid, and it sets \
the signature's creation time to the reference time instead of the \
current time.
",
    after_help = SIGN_EXAMPLES,
)]
#[clap(group(ArgGroup::new("kind")
             .args(&["detached", "message", "cleartext"]).required(true)))]
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

    #[clap(
        long = "signature-file",
        value_name = "SIG",
        help = "Create a detached signature file",
        conflicts_with = "output",
    )]
    pub detached: Option<FileOrStdout>,

    #[clap(
        long = "message",
        help = "Create an inline-signed message",
    )]
    pub message: bool,

    #[clap(
        long = "cleartext",
        help = "Create a cleartext-signed message",
        conflicts_with_all = &[
            "append",
            "notarize",
            "binary",
        ],
    )]
    pub cleartext: bool,

    #[clap(
        long = "mode",
        default_value = "binary",
        conflicts_with = "cleartext",
        help = "Select the signature mode",
        long_help = "Select the signature mode

Signatures can be made in binary mode or in text mode.  \
Text mode normalizes line endings, which makes signatures \
more robust when a text is transported over a channel which \
may change line endings.  In doubt, create binary signatures.",
    )]
    pub mode: Mode,

    #[clap(
        long,
        conflicts_with = "notarize",
        help = "Append a signature to existing signature",
    )]
    pub append: bool,
    #[clap(
        hide = true,
        long,
        conflicts_with = "append",
        help = "Sign a message and all existing signatures",
    )]
    pub notarize: bool,
    #[clap(
        long,
        value_name = "SIGNED-MESSAGE",
        conflicts_with_all = &[
            "append",
            "detached",
            "cleartext",
            "notarize",
            "signer",
            "signer-file",
            "signer-email",
            "signer-userid",
        ],
        help = "Merge signatures from the input and SIGNED-MESSAGE",
    )]
    pub merge: Option<PathBuf>,

    #[command(flatten)]
    pub signers: CertDesignators<CertUserIDEmailFileSelfArgs,
                                 SignerPrefix,
                                 // XXX: should be NoOptions, but we
                                 // cannot express that one cert
                                 // designator must be given unless
                                 // merge is given.
                                 OptionalValue,
                                 SignerDoc>,

    #[command(flatten)]
    pub signature_notations: crate::cli::types::SignatureNotationsArg,
}

/// Documentation for signer arguments.
pub struct SignerDoc {}
impl AdditionalDocs for SignerDoc {
    fn help(arg: &'static str, help: &'static str) -> clap::builder::StyledStr {
        match arg {
            "file" =>
                "Create the signature using the key read from PATH"
                .into(),
            _ => {
                debug_assert!(help.starts_with("Use certificates"));
                help.replace("Use certificates",
                             "Create the signature using the key")
                    .into()
            },
        }
    }
}

/// Signature mode, either binary or text.
#[derive(ValueEnum, Clone, Copy, Debug, Default)]
pub enum Mode {
    /// Create binary signatures.
    #[default]
    Binary,

    /// Create text signatures.
    Text,
}

impl From<Mode> for SignatureType {
    fn from(m: Mode) -> Self {
        match m {
            Mode::Binary => SignatureType::Binary,
            Mode::Text => SignatureType::Text,
        }
    }
}
