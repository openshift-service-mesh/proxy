//! Command-line parser for `sq decrypt`.

use std::path::PathBuf;

use clap::Parser;

use super::types::ClapData;
use super::types::FileOrStdin;
use super::types::FileOrStdout;
use super::types::SessionKey;
use super::types::cert_designator::*;

use crate::cli::examples;
use examples::Action;
use examples::Actions;

const DECRYPT_EXAMPLES: Actions = Actions {
    actions: &[
        Action::example().comment(
            "Decrypt a file using a secret key",
        ).command(&[
            "sq", "decrypt",
            "--recipient-file", "juliet-secret.pgp", "ciphertext.pgp",
        ]).build(),

        Action::example().comment(
            "Decrypt a file verifying signatures",
        ).command(&[
            "sq", "decrypt",
            "--recipient-file", "juliet-secret.pgp",
            "--signer-file", "romeo.pgp",
            "ciphertext.pgp"
        ]).build(),

        Action::setup().command(&[
            "sq", "key", "import", "juliet-secret.pgp",
        ]).build(),

        Action::example().comment(
            "decrypt a file using the key store",
        ).command(&[
            "sq", "decrypt", "ciphertext.pgp",
        ]).build(),
    ],
};
test_examples!(sq_decrypt, DECRYPT_EXAMPLES);

#[derive(Parser, Debug)]
#[clap(
    name = "decrypt",
    about = "Decrypt a message",
    long_about =
"Decrypt a message

Decrypt a message using either supplied keys, or by prompting for a \
password.  If message tampering is detected, an error is returned. \
See below for details.

If certificates are supplied using the `--signer-file` option, any \
signatures that are found are checked using these certificates. \
Verification is only successful if there is no bad signature, and the \
number of successfully verified signatures reaches the threshold \
configured with the `--signatures` parameter.

If the signature verification fails, or if message tampering is \
detected, the program terminates with an exit status indicating \
failure.  and the output file is deleted.  If the output was sent \
to stdout, then the last 25 MiB of the message are withheld \
(consequently, if the message is smaller than 25 MiB, no output \
is produced).

The converse operation is `sq encrypt`.
",
    after_help = DECRYPT_EXAMPLES,
)]
// TODO use usize
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
        long = "signatures",
        value_name = "N",
        help = "Set the threshold of valid signatures to N",
        long_help =
            "Set the threshold of valid signatures to N

The message will only be considered \
verified if this threshold is reached. \
[default: 1 if at least one signer cert file is given, 0 otherwise]",
    )]
    pub signatures: Option<usize>,

    #[command(flatten)]
    pub signers: CertDesignators<FileCertUserIDEmailDomainArgs,
                                 SignerPrefix,
                                 OptionalValue,
                                 ToVerifyDoc>,

    #[clap(
        long = "recipient-file",
        value_name = "KEY_FILE",
        help = "Decrypt the message using the key in KEY_FILE",
    )]
    pub secret_key_file: Vec<PathBuf>,
    #[clap(
            long = "dump-session-key",
            help = "Print the session key to stderr",
    )]
    pub dump_session_key: bool,
    #[clap(
        long = "session-key",
        value_name = "SESSION-KEY",
        help = "Decrypt an encrypted message using SESSION-KEY",
    )]
    pub session_key: Vec<SessionKey>,
}
