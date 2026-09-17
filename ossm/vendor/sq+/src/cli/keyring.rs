//! Command-line parser for `sq keyring`.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;

use crate::cli::examples::*;
use crate::cli::types::ClapData;
use crate::cli::types::FileOrStdin;
use crate::cli::types::FileOrStdout;

#[derive(Parser, Debug)]
#[clap(
    name = "keyring",
    about = "Manage collections of keys or certs",
    long_about =
"Manage collections of keys or certs

Collections of keys or certificates (also known as \"keyrings\" when \
they contain secret key material, and \"certrings\" when they don't) are \
any number of concatenated certificates.  This subcommand provides \
tools to list, split, merge, and filter keyrings.

Note: In the documentation of this subcommand, we sometimes use the \
terms keys and certs interchangeably.
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
    List(ListCommand),
    Split(SplitCommand),
    Merge(MergeCommand),
    Filter(FilterCommand),
}

#[derive(Debug, Args)]
#[clap(
    about = "Join keys into a keyring applying a filter",
    long_about =
"Join keys into a keyring applying a filter

This can be used to filter keys based on given predicates, \
e.g. whether they have a user id containing an email address with a \
certain domain.  Additionally, the keys can be pruned to only include \
components matching the predicates.

If no filters are supplied, everything matches.

If multiple predicates are given, they are or'ed, i.e., a key matches \
if any of the predicates match.  To require all predicates to match, \
chain multiple invocations of this command.  See EXAMPLES for \
inspiration.

Note: this command is considered experimental and may change in future \
releases.  To acknowledge this, you must give the `--experimental` \
flag when invoking this command.
",
    after_help = FILTER_EXAMPLES,
)]
pub struct FilterCommand {
    #[clap(
        long = "experimental",
        required = true,
        help = "Opt-in to using an experimental feature",
        long_help = "\
Opt-in to using an experimental feature

This command is considered experimental and may change in future \
releases.  To acknowledge this, you must give the `--experimental` \
flag when invoking this command.

In the future, we may stabilize this command.  When that happens, \
`--experimental` will no longer be required, but will be ignored \
silently.
",
    )]
    pub _experimental: bool,

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
        long = "userid",
        value_name = "USERID",
        help = "Match on USERID",
        long_help = "Match on USERID

Case-sensitively matches on the \
user ID, requiring an exact match.",
    )]
    pub userid: Vec<String>,
    #[clap(
        long = "name",
        value_name = "NAME",
        help = "Match on NAME",
        long_help = "Match on NAME

Parse user IDs into name and email \
and case-sensitively matches on the \
name, requiring an exact match.",
    )]
    pub name: Vec<String>,
    #[clap(
        long = "email",
        value_name = "ADDRESS",
        help = "Match on email ADDRESS",
        long_help = "Match on email ADDRESS

Parse user IDs into name and email \
address and case-sensitively matches \
on the email address, requiring an exact match.",
    )]
    pub email: Vec<String>,
    #[clap(
        long = "domain",
        value_name = "FQDN",
        help = "Match on email domain FQDN",
        long_help =
            "Match on email domain FQDN

Parse user IDs into name and email \
address and case-sensitively matches \
on the domain of the email address, \
requiring an exact match.",
    )]
    pub domain: Vec<String>,

    #[clap(
        long = "cert",
        value_name = "FINGERPRINT|KEYID",
        help = "Match on certificate fingerprints and key IDs",
        long_help =
            "Match on certificate fingerprints and key IDs

Match on primary keys, \
including those certificates that match the \
given fingerprint or key ID.",
    )]
    pub cert: Vec<KeyHandle>,

    #[clap(
        long = "key",
        value_name = "FINGERPRINT|KEYID",
        help = "Match on (sub)key fingerprints and key IDs",
        long_help =
            "Match on (sub)key fingerprints and key IDs

Match on both primary keys and subkeys, \
including those certificates that match the \
given fingerprint or key ID.",
    )]
    pub key: Vec<KeyHandle>,

    #[clap(
        long = "prune-certs",
        help = "Remove certificate components not matching the filter",
    )]
    pub prune_certs: bool,

    #[clap(
        long = "to-cert",
        help = "Convert any keys in the input to certificates",
        long_help =
            "Convert any keys in the input to certificates

Converting a key to a \
certificate removes secret key material \
from the key thereby turning it into \
a certificate.",
    )]
    pub to_certificate: bool,
}

const FILTER_EXAMPLES: Actions = Actions {
    actions: &[
        Action::setup().command(&[
            "sq", "keyring", "merge",
            "--output=certs.pgp",
            "bob.pgp", "romeo.pgp",
        ]).build(),

        Action::example().comment(
            "Convert all keys to certificates (i.e. remove any secret key material).",
        ).command(&[
            "sq", "keyring", "filter",
            "--experimental",
            "--to-cert",
            "certs.pgp",
        ]).build(),

        Action::example().comment(
            "Get all certificates with a user ID on example.org.",
        ).command(&[
            "sq", "keyring", "filter",
            "--experimental",
            "--domain=example.org",
            "certs.pgp",
        ]).build(),

        Action::example().comment(
            "Get all certificates with a user ID on example.org or example.net.",
        ).command(&[
            "sq", "keyring", "filter",
            "--experimental",
            "--domain=example.org",
            "--domain=example.net",
            "certs.pgp",
        ]).build(),

        Action::example().comment(
            "Get all certificates with a name user ID matching Romeo.",
        ).command(&[
            "sq", "keyring", "filter",
            "--experimental",
            "--name=Romeo",
            "certs.pgp",
        ]).build(),

        Action::example().comment(
            "Get all certificates with a name user ID matching Romeo on example.org.",
        ).command(&[
            "sq", "keyring", "filter",
            "--experimental",
            "--domain=example.org",
            "certs.pgp",
            "|", "sq", "keyring", "filter",
            "--experimental",
            "--name=Romeo",
        ]).build(),

        Action::example().comment(
            "Get all certificates with a user ID on example.org, pruning other user IDs.",
        ).command(&[
            "sq", "keyring", "filter",
            "--experimental",
            "--domain=example.org",
            "--prune-certs",
            "certs.pgp",
        ]).build(),
    ],
};
test_examples!(sq_keyring_filter, FILTER_EXAMPLES);

#[derive(Debug, Args)]
#[clap(
    about = "Merge keys or keyrings into a single keyring",
    long_about =
"Merge keys or keyrings into a single keyring

Multiple \
versions of the same certificate are merged together.  Where data is \
replaced (e.g., secret key material), data from the later certificate \
is preferred.
",
    after_help = MERGE_EXAMPLES,
)]
pub struct MergeCommand {
    #[clap(value_name = "FILE", help = "Read from FILE or stdin if omitted")]
    pub input: Vec<PathBuf>,
    #[clap(
        default_value_t = FileOrStdout::default(),
        help = FileOrStdout::HELP_OPTIONAL,
        long,
        value_name = FileOrStdout::VALUE_NAME,
    )]
    pub output: FileOrStdout,
}

const MERGE_EXAMPLES: Actions = Actions {
    actions: &[
        Action::setup().command(&[
            "sq", "packet", "dearmor",
            "--output=bob-updates.pgp",
            "bob.pgp",
        ]).build(),

        Action::example().comment(
            "Merge certificate updates.",
        ).command(&[
            "sq", "keyring", "merge",
            "bob.pgp", "bob-updates.pgp",
        ]).build(),
    ],
};
test_examples!(sq_keyring_merge, MERGE_EXAMPLES);

#[derive(Debug, Args)]
#[clap(
    about = "List keys in a keyring",
    long_about =
"List keys in a keyring

Prints the fingerprint as well as the primary userid for every \
certificate encountered in the keyring.
",
    after_help = LIST_EXAMPLES,
)]
pub struct ListCommand {
    #[clap(
        default_value_t = FileOrStdin::default(),
        help = FileOrStdin::HELP_OPTIONAL,
        value_name = FileOrStdin::VALUE_NAME,
    )]
    pub input: FileOrStdin,
    #[clap(
        long = "all-userids",
        help = "List all user IDs",
        long_help = "List all user IDs

Include user IDs that are \
expired, revoked, or not valid under the \
standard policy.",
    )]
    pub all_userids: bool,
}

const LIST_EXAMPLES: Actions = Actions {
    actions: &[
        Action::setup().command(&[
            "sq", "keyring", "merge",
            "--output=certs.pgp",
            "bob.pgp", "romeo.pgp",
        ]).build(),

        Action::example().comment(
            "List all certificates.",
        ).command(&[
            "sq", "keyring", "list",
            "certs.pgp",
        ]).build(),

        Action::example().comment(
            "List all certificates with a user ID on example.org.",
        ).command(&[
            "sq", "keyring", "filter",
            "--experimental",
            "--domain=example.org",
            "certs.pgp",
            "|", "sq", "keyring", "list",
        ]).build(),
    ],
};
test_examples!(sq_keyring_list, LIST_EXAMPLES);

#[derive(Debug, Args)]
#[clap(
    about = "Split a keyring into individual keys",
    long_about =
"Split a keyring into individual keys

Splitting up a keyring into individual keys helps with curating a \
keyring.

The converse operation is `sq keyring merge`.
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
        long = "prefix",
        value_name = "PREFIX",
        help = "Write to files with PREFIX \
            [defaults: `FILE-` if FILE is set, or `output-` if read from stdin]",
    )]
    pub prefix: Option<String>,
}

const SPLIT_EXAMPLES: Actions = Actions {
    actions: &[
        Action::setup().command(&[
            "sq", "keyring", "merge",
            "--output=certs.pgp",
            "bob.pgp", "romeo.pgp",
        ]).build(),

        Action::example().comment(
            "Split all certificates.",
        ).command(&[
            "sq", "keyring", "split",
            "certs.pgp",
        ]).build(),

        Action::example().comment(
            "Split all certificates, merging them first to avoid duplicates.",
        ).command(&[
            "sq", "keyring", "merge",
            "certs.pgp",
            "|", "sq", "keyring", "split",
        ]).build(),
    ],
};
test_examples!(sq_keyring_split, SPLIT_EXAMPLES);
