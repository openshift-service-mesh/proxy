use std::path::PathBuf;
use clap::{Args, Parser, Subcommand};

use sequoia_net::wkd;

use crate::cli::types::ClapData;
use crate::cli::types::FileOrCertStore;
use crate::cli::types::FileOrStdout;
use crate::cli::types::cert_designator::{
    CertDesignators,
    CertUserIDEmailFileArgs,
    CertPrefix,
    OptionalValue,
};

use crate::cli::examples::*;

#[derive(Parser, Debug)]
#[clap(
    name = "wkd",
    about = "Retrieve and publishes certificates via Web Key Directories",
    long_about =
"Retrieve and publishes certificates via Web Key Directories

The Web Key Directory (WKD) is a method for publishing and retrieving \
certificates from web servers.
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
    Publish(PublishCommand),
}

#[derive(Debug, Args)]
#[clap(
    about = "Retrieve certificates from a Web Key Directory",
    long_about =
"Retrieve certificates from a Web Key Directory

By default, any returned certificates are stored in the local \
certificate store.  This can be overridden by using `--output` \
option.

When a certificate is retrieved from a WKD, and imported into the \
local certificate store, any User IDs with the email address that was \
looked up are certificated with a local WKD-specific key.  That proxy \
certificate is in turn certified as a minimally trusted CA (trust \
amount: 1 of 120) by the local trust root.  How much the WKD proxy CA \
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
            "Retrieve Alice's certificate over WKD."
        ).command(&[
            "sq", "network", "wkd", "search", "alice@example.org",
        ]).syntax_check(),

        Action::example().comment(
            "Retrieve updates for all known certificates over WKD."
        ).command(&[
            "sq", "network", "wkd", "search", "--all",
        ]).syntax_check(),
    ],
};
test_examples!(sq_network_wkd_search, SEARCH_EXAMPLES);

const PUBLISH_EXAMPLES: Actions = Actions {
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
            "Create a new WKD hierarchy in the local directory \
             `public_html`, and insert Alice's cert.",
        ).command(&[
            "sq", "network", "wkd", "publish", "--create",
            "--cert=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            "--domain=example.org", "public_html",
        ]).build(),

        Action::example().comment(
            "Add Bob's cert to the existing WKD hierarchy \
             in the local directory `public_html`.",
        ).command(&[
            "sq", "network", "wkd", "publish",
            "--cert=511257EBBF077B7AEDAE5D093F68CB84CE537C9A",
            "--domain=example.org", "public_html",
        ]).build(),

        Action::example().comment(
            "Add all certs with an authenticated user ID \
             in example.org to the existing WKD hierarchy.",
        ).command(&[
            "sq", "network", "wkd", "publish",
            "--domain=example.org",
            "--all",
            "public_html",
        ]).build(),

        Action::example().comment(
            "Refresh all certs in the existing WKD hierarchy \
             in the local directory `public_html` from the \
             cert store.",
        ).command(&[
            "sq", "network", "wkd", "publish",
            "--domain=example.org", "public_html",
        ]).build(),
    ],
};

test_examples!(sq_network_wkd_publish, PUBLISH_EXAMPLES);

#[derive(Debug, Args)]
#[clap(
    about = "Publish certificates in a Web Key Directory",
    long_about =
"Publish certificates in a Web Key Directory

Publishes certificates or certificate updates in a Web Key Directory \
(WKD).  You can create or update a WKD hierarchy on the local system by \
specifying a path as destination.

Typically, a WKD is stored on a web server.  If `--rsync` is given, this \
command manages remote WKD directory hierarchies by using rsync(1).

To insert a new certificate into the WKD, use `--cert`.

Any updates for certificates already existing in the WKD are \
automatically published.

Note: To update a WKD hierarchy, it is first copied to a temporary \
location on the local machine, new certificates or certificate updates \
are inserted into the local copy, and the hierarchy is copied back to \
its original location.  As this is not an atomic operation, care must \
be taken to avoid concurrent updates.
",
    after_help = PUBLISH_EXAMPLES,
)]
pub struct PublishCommand {
    #[command(flatten)]
    pub certs: CertDesignators<CertUserIDEmailFileArgs,
                               CertPrefix,
                               OptionalValue>,

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
        long = "create",
        help = "Create the WKD hierarchy if it does not exist yet",
    )]
    pub create: bool,

    #[clap(
        long = "method",
        value_name = "METHOD",
        requires = "create",
        help = "Select kind of WKD hierarchy to be created",
        long_help = "Select kind of WKD hierarchy to be created

The advanced method, which is the default and should be preferred, \
is hosted on a separate domain (e.g. openpgpkey.example.org).

The direct method is hosted on the same domain (e.g. example.org).",
    )]
    pub method: Option<Method>,

    #[clap(
        long = "rsync",
        help = "Use rsync(1) to access DEST",
    )]
    pub rsync: bool,

    #[clap(
        long = "rsync-path",
        value_name = "RSYNC",
        help = "Path to the local rsync command to use, implies --rsync",
    )]
    pub rsync_path: Option<PathBuf>,

    #[clap(
        long = "domain",
        value_name = "FQDN",
        help = "Generate a WKD for a fully qualified domain name for email",
    )]
    pub domain: String,
    #[clap(
        value_name = "DEST",
        help = "Location of the WKD on the local or remote machine",
        long_help = "Location of the WKD on the local or remote machine

If --rsync is given, this is passed as-is to rsync(1).",
    )]
    pub destination: String,
}

#[derive(clap::ValueEnum, Debug, Clone, Copy, Default)]
pub enum Method {
    /// Create a WKD using the advanced method.
    #[default]
    Advanced,

    /// Create a WKD using the direct method.
    Direct,
}

impl From<Method> for wkd::Variant {
    fn from(v: Method) -> wkd::Variant {
        match v {
            Method::Advanced => wkd::Variant::Advanced,
            Method::Direct => wkd::Variant::Direct,
        }
    }
}
