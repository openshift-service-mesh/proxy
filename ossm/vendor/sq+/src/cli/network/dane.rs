use std::time::Duration;

use clap::{Args, Parser, Subcommand};

use crate::cli::types::ClapData;
use crate::cli::types::FileOrCertStore;
use crate::cli::types::FileOrStdout;
use crate::cli::types::cert_designator::{
    CertDesignators,
    CertUserIDEmailFileArgs,
    CertOrAll,
    CertPrefix,
};

use crate::cli::examples::*;

#[derive(Parser, Debug)]
#[clap(
    name = "dane",
    about = "Retrieve and publishes certificates via DANE",
    long_about =
"Retrieve and publishes certificates via DANE

DNS-Based Authentication of Named Entities (DANE) is a method for \
publishing and retrieving certificates in DNS as specified in RFC \
7929.
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
    Search(SearchCommand),
    Generate(GenerateCommand),
}

const GENERATE_EXAMPLES: Actions = Actions {
    actions: &[
        Action::setup().command(&[
            "sq", "cert", "import", "juliet.pgp",
        ]).build(),

        Action::setup().command(&[
            "sq", "pki", "link", "add",
            "--cert=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            "--userid=Alice <alice@example.org>",
        ]).build(),

        Action::example().comment(
            "Generate DANE records from juliet.pgp for example.org.",
        ).command(&[
            "sq", "network", "dane", "generate",
            "--domain=example.org",
            "--cert-file=juliet.pgp",
        ]).build(),

        Action::example().comment(
            "Generate DANE records for all certs with an authenticated \
             user ID in example.org.",
        ).command(&[
            "sq", "network", "dane", "generate",
            "--domain=example.org",
            "--all",
        ]).build(),
    ],
};
test_examples!(sq_network_dane_generate, GENERATE_EXAMPLES);

#[derive(Debug, Args)]
#[clap(
    about = "Generate DANE records for the given domain and certs",
    long_about =
"Generate DANE records for the given domain and certs

The certificates are minimized, and one record per email address is \
emitted.  If multiple user IDs map to one email address, then all \
matching user IDs are included in the emitted certificates.

By default, OPENPGPKEY resource records are emitted.  If your DNS \
server doesn't understand those, use `--type generic` to emit generic \
records instead.
",
    after_help = GENERATE_EXAMPLES,
)]
pub struct GenerateCommand {
    #[command(flatten)]
    pub certs: CertDesignators<CertUserIDEmailFileArgs,
                               CertPrefix,
                               CertOrAll>,

    #[clap(
        long = "all",
        help = "Publish authenticated certs with a user ID matching domain",
        long_help = "\
Publish authenticated certs with a user ID matching domain

Use all certificates that have a user ID matching the domain given \
to the `--domain` parameter that can be fully authenticated.",
    )]
    pub all: bool,

    #[clap(
        long = "domain",
        value_name = "FQDN",
        help = "Generate DANE records for this domain name",
    )]
    pub domain: String,

    #[clap(
        long = "ttl",
        value_name = "DURATION",
        value_parser = |arg: &str| -> Result<Duration, std::num::ParseIntError>
            { Ok(Duration::from_secs(arg.parse()?)) },
        default_value = "10800",
        help = "Set the TTL (maximum cache duration) of the resource records",
    )]
    pub ttl: Duration,
    #[clap(
        long = "size-limit",
        value_name = "BYTES",
        default_value = "12288",
        help = "Try to shrink the certificates to this size",
    )]
    pub size_limit: usize,

    #[clap(
        long = "type",
        value_name = "TYPE",
        default_value = "openpgp",
        help = "Change the emitted resource record type",
    )]
    pub typ: ResourceRecordType,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ResourceRecordType {
    #[default]
    #[clap(name = "openpgp")]
    OpenPGP,
    Generic,
}

#[derive(Debug, Args)]
#[clap(
    about = "Retrieve certificates using DANE",
    long_about =
"Retrieve certificates using DANE

By default, any returned certificates are stored in the local \
certificate store.  This can be overridden by using `--output` \
option.

When a certificate is retrieved using DANE, and imported into the \
local certificate store, any User IDs with the email address that was \
looked up are certificated with a local DANE-specific key.  That proxy \
certificate is in turn certified as a minimally trusted CA (trust \
amount: 1 of 120) by the local trust root.  How much the DANE proxy CA \
is trusted can be tuned using `sq pki link add` or `sq pki link retract` \
in the usual way.
",
    after_help = SEARCH_EXAMPLES,
)]
pub struct SearchCommand {
    #[clap(
        long,
        conflicts_with = "addresses",
        help = "Fetch updates for all known certificates",
    )]
    pub all: bool,

    #[clap(
        value_name = "ADDRESS",
        required = true,
        help = "Retrieve certificate(s) for ADDRESS",
    )]
    pub addresses: Vec<String>,

    #[clap(
        help = FileOrCertStore::HELP_OPTIONAL,
        long,
        value_name = FileOrCertStore::VALUE_NAME,
    )]
    pub output: Option<FileOrStdout>,
}

const SEARCH_EXAMPLES: Actions = Actions {
    actions: &[
        Action::example().comment(
            "Retrieve Alice's certificate over DANE."
        ).command(&[
            "sq", "network", "dane", "search", "alice@example.org",
        ]).syntax_check(),

        Action::example().comment(
            "Retrieve updates for all known certificates over DANE."
        ).command(&[
            "sq", "network", "dane", "search", "--all",
        ]).syntax_check(),
    ],
};
test_examples!(sq_network_dane_search, SEARCH_EXAMPLES);
