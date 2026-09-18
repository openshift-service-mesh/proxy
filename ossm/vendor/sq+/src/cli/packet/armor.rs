use clap::Parser;

use crate::cli::examples::*;
use crate::cli::types::ArmorKind;
use crate::cli::types::ClapData;
use crate::cli::types::FileOrStdin;
use crate::cli::types::FileOrStdout;

// TODO?: Option<_> conflicts with default value
// TODO: use indoc to transparently (de-)indent static strings
#[derive(Parser, Debug)]
#[clap(
    name = "armor",
    about = "Convert binary to ASCII",
    long_about =
"Convert binary to ASCII

To make encrypted data easier to handle and transport, OpenPGP data \
can be transformed to an ASCII representation called ASCII Armor.  sq \
emits armored data by default, but this subcommand can be used to \
convert existing OpenPGP data to its ASCII-encoded representation.

The converse operation is `sq packet dearmor`.
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
    #[clap(
        long = "label",
        value_name = "LABEL",
        help = "Select the kind of armor header",
        default_value_t = ArmorKind::Auto,
        value_enum
    )]
    pub kind: ArmorKind,
}

const EXAMPLES: Actions = Actions {
    actions: &[
        Action::setup().command(&[
            "sq", "packet", "dearmor",
            "--output=message.bin",
            "message.pgp",
        ]).build(),

        Action::example().comment(
            "Convert a binary OpenPGP message to an ASCII armored OpenPGP message.",
        ).command(&[
            "sq", "packet", "armor",
            "message.bin",
        ]).build(),

        Action::example().comment(
            "Convert a binary OpenPGP message to an ASCII armored OpenPGP message
explicitly choosing the armor label.",
        ).command(&[
            "sq", "packet", "armor",
            "--label=message",
            "message.bin",
        ]).build(),
    ],
};
test_examples!(sq_packet_armor, EXAMPLES);
