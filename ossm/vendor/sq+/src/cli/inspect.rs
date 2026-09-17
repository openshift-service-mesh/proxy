//! Command-line parser for `sq inspect`.

use clap::Parser;

use super::types::ClapData;
use super::types::FileOrStdin;
use super::types::cert_designator::*;

use crate::cli::examples;
use examples::Action;
use examples::Actions;

const INSPECT_EXAMPLES: Actions = Actions {
    actions: &[
        Action::example().comment(
            "Inspect a certificate.",
        ).command(&[
            "sq", "inspect", "juliet.pgp",
        ]).build(),

        Action::example().comment(
            "Show how the certificate looked on July 21, 2013.",
        ).command(&[
            "sq", "inspect", "--time", "20130721", "juliet.pgp",
        ]).build(),

        Action::example().comment(
            "Inspect an encrypted message.",
        ).command(&[
            "sq", "inspect", "message.pgp",
        ]).build(),

        Action::example().comment(
            "Inspect a detached signature.",
        ).command(&[
            "sq", "inspect", "document.sig",
        ]).build(),
    ],
};
test_examples!(sq_inspect, INSPECT_EXAMPLES);

#[derive(Parser, Debug)]
#[clap(
    name = "inspect",
    about = "Inspect data, like file(1)",
    long_about =
"Inspect data, like file(1)

It is often difficult to tell from cursory inspection using cat(1) or \
file(1) what kind of OpenPGP one is looking at.  This subcommand \
inspects the data and provides a meaningful human-readable description \
of it.

`sq inspect` respects the reference time set by the top-level \
`--time` argument.  It uses the reference time when determining what \
binding signatures are active.
",
    after_help = INSPECT_EXAMPLES,
)]
pub struct Command {
    #[clap(
        default_value_t = FileOrStdin::default(),
        help = FileOrStdin::HELP_OPTIONAL,
        value_name = FileOrStdin::VALUE_NAME,
        conflicts_with_all = ["cert-file", "cert", "cert-userid", "cert-email", "cert-domain", "cert-grep"],
    )]
    pub input: FileOrStdin,

    #[command(flatten)]
    pub certs: CertDesignators<FileCertUserIDEmailDomainGrepArgs,
                               CertPrefix,
                               OptionalValue,
                               ToInspectDoc>,

    #[clap(
        long = "certifications",
        help = "Print third-party certifications",
    )]
    pub certifications: bool,

    #[clap(
        long = "dump-bad-signatures",
        help = "Dump signatures that are definitively bad",
    )]
    pub dump_bad_signatures: bool,
}

/// Documentation for the cert designators for `--inspect`.
pub struct ToInspectDoc {}

impl AdditionalDocs for ToInspectDoc {
    fn help(arg: &'static str, help: &'static str) -> clap::builder::StyledStr {
        let help = help.replace("Use", "Inspect");
        match arg {
            "cert" | "file" => help,
            _ => format!(
                "{} (note: User IDs are not authenticated)",
                help),
        }.into()
    }
}
