use clap::Parser;

use crate::cli::examples::*;
use crate::cli::types::ClapData;
use crate::cli::types::FileOrStdin;
use crate::cli::types::FileOrStdout;

#[derive(Parser, Debug)]
#[clap(
    name = "dearmor",
    about = "Convert ASCII to binary",
    long_about =
"Convert ASCII to binary

To make encrypted data easier to handle and transport, OpenPGP data \
can be transformed to an ASCII representation called ASCII Armor.  sq \
transparently handles armored data, but this subcommand can be used to \
explicitly convert existing ASCII-encoded OpenPGP data to its binary \
representation.

The converse operation is `sq packet armor`.
",
    after_help = EXAMPLES,
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
}

const EXAMPLES: Actions = Actions {
    actions: &[
        Action::example().comment(
            "Convert an ASCII armored OpenPGP message to a binary OpenPGP message.",
        ).command(&[
            "sq", "packet", "dearmor",
            "--output=message.bin",
            "message.pgp",
        ]).build(),
    ],
};
test_examples!(sq_packet_dearmor, EXAMPLES);
