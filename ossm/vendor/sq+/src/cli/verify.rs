//! Command-line parser for `sq verify`.

use std::path::PathBuf;

use clap::{ArgGroup, Parser};

use super::types::ClapData;
use super::types::FileOrStdin;
use super::types::FileOrStdout;
use super::types::cert_designator::*;

use crate::cli::examples;
use examples::*;

const VERIFY_EXAMPLES: Actions = Actions {
    actions: &[
        Action::setup().command(&[
            "sq", "cert", "import", "juliet.pgp",
        ]).build(),

        Action::setup().command(&[
            "sq", "--time", "2024-06-19",
            "pki", "link", "add",
            "--cert", "7A58B15E3B9459483D9FFA8D40E299AC5F2B0872",
            "--email", "juliet@example.org",
        ]).build(),

        Action::example().comment(
            "Verify a signed message.",
        ).command(&[
            "sq", "verify", "--message", "document.pgp",
        ]).build(),

        Action::example().comment(
            "Verify a detached signature.",
        ).command(&[
            "sq", "verify", "--signature-file=document.sig", "document.txt",
        ]).build(),

        Action::example().comment(
            "Verify a message as of June 19, 2024 at midnight UTC.",
        ).command(&[
            "sq", "verify", "--time", "2024-06-19",
            "--message", "document.pgp",
        ]).build(),
    ],
};
test_examples!(sq_verify, VERIFY_EXAMPLES);

#[derive(Parser, Debug)]
#[clap(
    name = "verify",
    about = "Verify signed messages or detached signatures",
    long_about = "Verify signed messages or detached signatures

When verifying signed messages, the message is written to stdout or \
the file given to `--output`.

When a detached message is verified, no output is produced.  Detached \
signatures are often used to sign software packages.

Verification is only successful if there is no bad signature, and the \
number of successfully verified signatures reaches the threshold \
configured with the `--signatures` parameter.  If the verification \
fails, the program terminates with an exit status indicating failure, \
and the output file is deleted.  If the output was sent to stdout, \
then the last 25 MiB of the message are withheld (consequently, if \
the message is smaller than 25 MiB, no output is produced).

A signature is considered to have been authenticated if the signer can \
be authenticated.  If the signer is provided via `--signer-file`, \
then the signer is considered authenticated.  Otherwise, the signer is \
looked up and authenticated using the Web of Trust.  If at least one \
User ID can be fully authenticated, then the signature is considered \
to have been authenticated.  If the signature includes a Signer User \
ID subpacket, then only that User ID is considered.  Note: the User ID \
need not be self signed.

The converse operation is `sq sign`.

If you are looking for a standalone program to verify detached \
signatures, consider using sequoia-sqv.

`sq verify` respects the reference time set by the top-level \
`--time` argument.  When set, it verifies the message as of the \
reference time instead of the current time.
",
    after_help = VERIFY_EXAMPLES,
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
        conflicts_with = "detached",
    )]
    pub output: FileOrStdout,

    #[clap(
        long = "signature-file",
        value_name = "SIG",
        help = "Verify a detached signature file"
    )]
    pub detached: Option<PathBuf>,

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

    #[command(flatten)]
    pub signers: CertDesignators<FileCertUserIDEmailDomainArgs,
                                 SignerPrefix,
                                 OptionalValue,
                                 ToVerifyDoc>,
}
