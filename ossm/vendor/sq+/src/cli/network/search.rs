use clap::Parser;

use crate::cli::config;
use crate::cli::examples::Action;
use crate::cli::examples::Actions;

use crate::cli::types::ClapData;
use crate::cli::types::FileOrCertStore;
use crate::cli::types::FileOrStdout;
use super::keyserver::DEFAULT_KEYSERVERS;

#[derive(Parser, Debug)]
#[clap(
    name = "search",
    about = "Retrieve certificates using all supported network services",
    long_about =
"Retrieve certificates using all supported network services

This command will try to locate relevant certificates given a query, \
which may be a fingerprint, a key ID, an email address, or a https \
URL.  It may also discover and import certificate related to the one \
queried, such as alternative certs, expired certs, or revoked certs.

Discovering related certs is useful: alternative certs support key \
rotations, expired certs allow verification of signatures made in the \
past, and discovering revoked certs is important to get the revocation \
information.  The PKI mechanism will help to select the correct cert, \
see `sq pki`.

By default, any returned certificates are stored in the local \
certificate store.  This can be overridden by using `--output` \
option.

When a certificate is retrieved from a verifying key server (currently, \
this is limited to a list of known servers: `hkps://keys.openpgp.org`, \
`hkps://keys.mailvelope.com`, and `hkps://mail-api.proton.me`), \
WKD, DANE, or via https, and \
imported into the local certificate store, the User IDs are also \
certificated with a local server-specific key.  That proxy certificate \
is in turn certified as a minimally trusted CA (trust amount: 1 of \
120) by the local trust root.  How much a proxy key server CA is \
trusted can be tuned using `sq pki link add` or `sq pki link retract` in \
the usual way.
",
    arg_required_else_help = true,
    after_help = EXAMPLES,
)]
pub struct Command {
    #[clap(
        long = "iterations",
        value_name = "N",
        default_value_t = 3,
        help = "Iterate to find related updates and certs",
        long_help = config::augment_help(
            "network.search.iterations",
            "Iterate to find related updates and certs"),
    )]
    pub iterations: u8,

    /// Workaround for https://github.com/clap-rs/clap/issues/3846
    #[clap(skip)]
    pub iterations_source: Option<clap::parser::ValueSource>,

    #[clap(
        long = "server",
        default_values_t = DEFAULT_KEYSERVERS.iter().map(ToString::to_string),
        value_name = "URI",
        help = "Set a key server to use (can be given multiple times)",
        long_help = config::augment_help(
            "network.keyserver.servers",
            "Set a key server to use (can be given multiple times)"),
    )]
    pub servers: Vec<String>,

    /// Workaround for https://github.com/clap-rs/clap/issues/3846
    #[clap(skip)]
    pub servers_source: Option<clap::parser::ValueSource>,

    #[clap(
        long = "use-wkd",
        value_name = "ENABLE",
        default_value = "true",
        help = "Use WKD to search for certs",
        long_help = config::augment_help(
            "network.search.use-wkd",
            "Use WKD to search for certs"),
    )]
    pub use_wkd: Option<bool>,

    /// Workaround for https://github.com/clap-rs/clap/issues/3846
    #[clap(skip)]
    pub use_wkd_source: Option<clap::parser::ValueSource>,

    #[clap(
        long = "use-dane",
        value_name = "ENABLE",
        default_value = "true",
        help = "Use DANE to search for certs",
        long_help = config::augment_help(
            "network.search.use-dane",
            "Use DANE to search for certs"),
    )]
    pub use_dane: Option<bool>,

    /// Workaround for https://github.com/clap-rs/clap/issues/3846
    #[clap(skip)]
    pub use_dane_source: Option<clap::parser::ValueSource>,

    #[clap(
        help = FileOrCertStore::HELP_OPTIONAL,
        long,
        value_name = FileOrCertStore::VALUE_NAME,
    )]
    pub output: Option<FileOrStdout>,

    #[clap(
        long,
        conflicts_with = "query",
        help = "Fetch updates for all known certificates",
    )]
    pub all: bool,

    #[clap(
        value_name = "QUERY",
        required = true,
        help = "Retrieve certificate(s) using QUERY",
        long_help = "Retrieve certificate(s) using QUERY

This may be a fingerprint, a KeyID, \
an email address, or a https URL.",
    )]
    pub query: Vec<String>,
}

const EXAMPLES: Actions = Actions {
    actions: &[
        Action::example().comment(
            "Search for the Qubes master signing certificate.",
        ).command(&[
            "sq", "network", "search",
            "427F11FD0FAA4B080123F01CDDFA1A3E36879494",
        ]).syntax_check(),

        Action::example().comment(
            "Search for certificates that have are associated \
             with an email address.",
        ).command(&[
            "sq", "network", "search", "alice@example.org",
        ]).syntax_check(),
    ],
};
test_examples!(sq_network_search, EXAMPLES);
