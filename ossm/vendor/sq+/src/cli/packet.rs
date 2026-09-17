//! Command-line parser for `sq packet`.

use std::{
    ffi::OsString,
    path::PathBuf,
};

use clap::{Args, Parser, Subcommand};

use crate::cli::examples::*;
use crate::cli::types::ArmorKind;
use crate::cli::types::ClapData;
use crate::cli::types::FileOrStdin;
use crate::cli::types::FileOrStdout;
use crate::cli::types::SessionKey;
use crate::cli::types::cert_designator::*;

pub mod armor;
pub mod dearmor;

#[derive(Parser, Debug)]
#[clap(
    name = "packet",
    about = "Low-level packet manipulation",
    long_about =
"Low-level packet manipulation

An OpenPGP data stream consists of packets.  These tools allow working \
with packet streams.  They are mostly of interest to developers, but \
`sq packet dump` may be helpful to a wider audience both to provide \
valuable information in bug reports to OpenPGP-related software, and \
as a learning tool.
",
    subcommand_required = true,
    arg_required_else_help = true,
    disable_help_subcommand = true,
)]
pub struct Command {
    #[clap(subcommand)]
    pub subcommand: Subcommands,
}

#[derive(Debug, Subcommand)]
pub enum Subcommands {
    Armor(armor::Command),
    Dearmor(dearmor::Command),
    Dump(DumpCommand),
    Decrypt(DecryptCommand),
    Split(SplitCommand),
    Join(JoinCommand),
}

#[derive(Debug, Args)]
#[clap(
    about = "List packets",
    long_about =
"List packets

Creates a human-readable description of the packet sequence. \
Additionally, it can print cryptographic artifacts, and print the raw \
octet stream similar to hexdump(1), annotating specifically which \
bytes are parsed into OpenPGP values.

If the packet stream includes an encryption container, `sq` will attempt \
to decrypt it.
",
    after_help = DUMP_EXAMPLES,
)]
pub struct DumpCommand {
    #[command(flatten)]
    pub cert: CertDesignators<CertUserIDEmailFileArgs,
                              CertPrefix,
                              OneOptionalValue,
                              PacketDumpDoc>,

    #[clap(
        default_value_t = FileOrStdin::default(),
        help = FileOrStdin::HELP_OPTIONAL,
        value_name = FileOrStdin::VALUE_NAME,
        conflicts_with_all = ["cert", "cert-userid", "cert-email", "cert-file"],
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
        long = "session-key",
        value_name = "SESSION-KEY",
        help = "Decrypt an encrypted message using SESSION-KEY",
    )]
    pub session_key: Vec<SessionKey>,

    #[clap(
        long = "recipient-file",
        value_name = "KEY_FILE",
        help = "Decrypt the message using the key in KEY_FILE",
    )]
    pub recipient_file: Vec<PathBuf>,

    #[clap(
        long = "mpis",
        help = "Print cryptographic artifacts",
    )]
    pub mpis: bool,
    #[clap(
        long = "hex",
        help = "Print a hexdump",
    )]
    pub hex: bool,
}

const DUMP_EXAMPLES: Actions = Actions {
    actions: &[
        Action::example().comment(
            "Print the packets of a certificate.",
        ).command(&[
            "sq", "packet", "dump",
            "juliet.pgp",
        ]).build(),

        Action::example().comment(
            "Print the packets including cryptographic artifacts of a certificate.",
        ).command(&[
            "sq", "packet", "dump",
            "--mpis", "juliet.pgp",
        ]).build(),

        Action::example().comment(
            "Print the packets including a dump of every byte of a certificate.",
        ).command(&[
            "sq", "packet", "dump",
            "--hex", "juliet.pgp",
        ]).build(),

        Action::example().comment(
            "Prints the packets of an encrypted message, decrypting it using a \
             secret key file.",
        ).command(&[
            "sq", "packet", "dump",
            "--recipient-file", "bob-secret.pgp",
            "message.pgp",
        ]).build(),
    ],
};
test_examples!(sq_packet_dump, DUMP_EXAMPLES);

/// Documentation for the cert designators for the packet dump
/// command.
pub struct PacketDumpDoc {}

impl AdditionalDocs for PacketDumpDoc {
    fn help(arg: &'static str, help: &'static str) -> clap::builder::StyledStr {
        match arg {
            "file" =>
                "Dump the packets of the cert read from PATH"
                .into(),
            _ => {
                debug_assert!(help.starts_with("Use certificates"));
                help.replace("Use certificates",
                             "Dump the packets of the certificate")
                    .into()
            },
        }
    }
}

#[derive(Debug, Args)]
#[clap(
    about = "Unwrap an encryption container",
    long_about = "Unwrap an encryption container

Decrypts a message, dumping the content of the encryption container \
without further processing.  The result is a valid OpenPGP message \
that can, among other things, be inspected using `sq packet dump`.
",
    after_help = DECRYPT_EXAMPLES,
)]
pub struct DecryptCommand {
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
        long = "recipient-file",
        value_name = "KEY_FILE",
        help = "Decrypt the message using the key in KEY_FILE",
    )]
    pub secret_key_file: Vec<PathBuf>,
    #[clap(
        long = "session-key",
        value_name = "SESSION-KEY",
        help = "Decrypt an encrypted message using SESSION-KEY",
    )]
    pub session_key: Vec<SessionKey>,
    #[clap(
            long = "dump-session-key",
            help = "Print the session key to stderr",
    )]
    pub dump_session_key: bool,
}

const DECRYPT_EXAMPLES: Actions = Actions {
    actions: &[
        Action::example().comment(
            "Unwrap the encryption revealing the signed message.",
        ).command(&[
            "sq", "packet", "decrypt",
            "--recipient-file", "bob-secret.pgp",
            "message.pgp",
        ]).build(),
    ],
};
test_examples!(sq_packet_decrypt, DECRYPT_EXAMPLES);

#[derive(Debug, Args)]
#[clap(
    about = "Split a message into packets",
    long_about = "Split a message into packets

Splitting a packet sequence into individual packets, then recombining \
them freely with `sq packet join` is a great way to experiment with \
OpenPGP data.

By default, the packets are written to stdout as a sequence of ASCII \
armored blocks.  It is possible to edit this file directly (e.g., \
moving, adding, or removing packets), and then use `sq packet \
join` to assemble the stream.

Alternatively, if a `--output-prefix` is given, the packets are written \
into individual files starting with the prefix, and can be reassembled \
with `sq packet join`.

The converse operation is `sq packet join`.
",
    after_help = SPLIT_EXAMPLES,
)]
pub struct SplitCommand {
    #[clap(
        default_value_t = FileOrStdin::default(),
        help = FileOrStdin::HELP_OPTIONAL,
        value_name = FileOrStdin::VALUE_NAME,
    )]
    pub input: FileOrStdin,

    #[clap(
        help = FileOrStdout::HELP_OPTIONAL,
        long,
        value_name = FileOrStdout::VALUE_NAME,
    )]
    pub output: Option<FileOrStdout>,

    #[clap(
        long = "binary",
        requires = "prefix",
        help = "Emit binary data",
    )]
    pub binary: bool,

    #[clap(
        long = "output-prefix",
        value_name = "PREFIX",
        help = "Write packets to files starting with PREFIX",
        help = "\
Write packets to individual files starting with the given prefix.

The file names are formed by joining the prefix, the path of the \
packet in the source object (recall: packets can be nested), and \
a human-readable packet type with dashes ('-').
",
    )]
    pub prefix: Option<OsString>,
}

const SPLIT_EXAMPLES: Actions = Actions {
    actions: &[
        Action::example().comment(
            "Split a certificate into individual packets printed to stdout.",
        ).command(&[
            "sq", "packet", "split",
            "--output=-",
            "juliet.pgp",
        ]).build(),

        Action::example().comment(
            "Split a inline-signed message into individual packets written to \
             individual files with the prefix 'packet'.",
        ).command(&[
            "sq", "packet", "split",
            "--output-prefix", "packet",
            "document.pgp",
        ]).build(),

        Action::example().comment(
            "Then reassemble the message, transforming it into an old-style \
             signed message with a prefix signature.",
        ).command(&[
            "sq", "packet", "join",
            "--output", "prefix-signature.pgp",
            "--label", "message",
            "packet-2-Signature-Packet",
            "packet-1-Literal-Data-Packet",
        ]).build(),
    ],
};
test_examples!(sq_packet_split, SPLIT_EXAMPLES);

#[derive(Debug, Args)]
#[clap(
    about = "Join packets split across files",
    long_about = "Join packets split across files

Splitting a packet sequence into individual packets, then recombining \
them freely with `sq packet join` is a great way to experiment with \
OpenPGP data.

The converse operation is `sq packet split`.
",
    after_help = JOIN_EXAMPLES,
)]
pub struct JoinCommand {
    #[clap(value_name = "FILE", help = "Read from FILE or stdin if omitted")]
    pub input: Vec<PathBuf>,
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
        default_value_t = ArmorKind::Auto,
        conflicts_with = "binary",
        help = "Select the kind of armor header",
        value_enum,
    )]
    pub kind: ArmorKind,
    #[clap(
        long,
        help = "Emit binary data",
    )]
    pub binary: bool,
}

const JOIN_EXAMPLES: Actions = Actions {
    actions: &[
        Action::example().comment(
            "Split a inline-signed message into individual packets written to \
             individual files with the prefix 'packet'.",
        ).command(&[
            "sq", "packet", "split",
            "--output-prefix", "packet",
            "document.pgp",
        ]).build(),

        Action::example().comment(
            "Then reassemble the message, transforming it into an old-style \
             signed message with a prefix signature.",
        ).command(&[
            "sq", "packet", "join",
            "--output", "prefix-signature.pgp",
            "--label", "message",
            "packet-2-Signature-Packet",
            "packet-1-Literal-Data-Packet",
        ]).build(),
    ],
};
test_examples!(sq_packet_join, JOIN_EXAMPLES);
