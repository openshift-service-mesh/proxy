//! Command-line parser for `sq download`.

use clap::{ArgGroup, Parser};

use crate::cli::examples;
use examples::Action;
use examples::Actions;

use super::types::ClapData;
use super::types::cert_designator::*;
use crate::cli::types::FileOrStdout;

const EXAMPLES: Actions = Actions {
    actions: &[
        Action::setup().command(&[
            "sq", "cert", "import", "debian/debian-cd-signing-key.pgp",
        ]).build(),

        Action::example().comment(
            "Download and verify the Debian 12 checksum file.",
        ).command(&[
            "sq", "download",
            "--url=file://debian/SHA512SUMS",
            "--signature-url=file://debian/SHA512SUMS.sign",
            "--signer=DF9B9C49EAA9298432589D76DA87E80D6294BE9B",
            "--output=SHA512SUMS",
        ]).build(),
    ],
};
test_examples!(sq_download, EXAMPLES);

#[derive(Parser, Debug)]
#[clap(
    name = "download",
    about = "Download and authenticate the data",
    long_about =
"Download and authenticate the data

This command downloads the data from the specified URL, checks the
signature, and then authenticates the signer.  If the signer cannot be
authenticated, the data is deleted, if possible.
",
    after_help = EXAMPLES,
)]
#[clap(group(ArgGroup::new("kind")
             .args(&["detached", "message", "cleartext"]).required(true)))]
pub struct Command {
    #[clap(
        long = "url",
        value_name = "URL",
        help = "The data to download",
    )]
    pub url: String,

    #[clap(
        long = "signature-url",
        value_name = "URL",
        help = "URL of the signature",
        long_help = "\
URL of the signature

Use this when the signature is detached from the data.

If no signature is specified, then the signature is assumed to be \
inline.
",
    )]
    pub detached: Option<String>,

    #[clap(
        long = "message",
        value_name = "SIG",
        help = "Verify an inline signed message"
    )]
    pub message: bool,

    #[clap(
        long = "cleartext",
        value_name = "SIG",
        help = "Verify a cleartext-signed message"
    )]
    pub cleartext: bool,

    #[command(flatten)]
    pub signers: CertDesignators<FileCertUserIDEmailDomainArgs,
                                 SignerPrefix,
                                 OptionalValue,
                                 ToVerifyDoc>,

    #[clap(
        long = "signatures",
        value_name = "N",
        default_value_t = 1,
        help = "Set the threshold of valid signatures to N",
        long_help = "Set the threshold of valid signatures to N

If this threshold is not reached, the message \
will not be considered verified.",
    )]
    pub signatures: usize,

    #[clap(
        help = FileOrStdout::HELP_REQUIRED,
        long,
        value_name = FileOrStdout::VALUE_NAME,
    )]
    pub output: FileOrStdout,
}
