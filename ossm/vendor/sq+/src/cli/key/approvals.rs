//! Command-line parser for `sq key expire`.

use clap::{
    Args,
    ArgGroup,
    Subcommand,
};

use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;

use crate::cli::types::ClapData;
use crate::cli::types::FileOrStdout;

use crate::cli::examples::*;
use crate::cli::types::cert_designator::*;
use crate::cli::types::UserIDDesignators;
use crate::cli::types::userid_designator;

#[derive(Debug, Subcommand)]
#[clap(
    name = "approvals",
    about = "Manages certification approvals",
    long_about = "\
Manages certification approvals

Key holders may approve of third-party certifications associated with \
their certificate.  This subcommand manages the approvals.

To prevent certificate flooding attacks, modern key servers prevent \
uncontrolled distribution of third-party certifications on \
certificates.  To allow the key holder to control what information is \
distributed with their certificate, these key servers only distribute \
third-party certifications that the key holder has explicitly \
approved.
",
    subcommand_required = true,
    arg_required_else_help = true,
    disable_help_subcommand = true,
)]
#[non_exhaustive]
pub enum Command {
    List(ListCommand),
    Update(UpdateCommand),
}

const LIST_EXAMPLES: Actions = Actions {
    actions: &[
        Action::Example(Example {
            comment: "\
Lists the approved certifications on all the user IDs.",
            command: &[
                "sq", "key", "approvals", "list",
                "--cert=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            ],
            hide: &[],
        }),

        Action::Example(Example {
            comment: "\
Lists the unapproved certifications on all the user IDs.",
            command: &[
                "sq", "key", "approvals", "list",
                "--pending",
                "--cert=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            ],
            hide: &[],
        }),

        Action::Example(Example {
            comment: "\
Lists all unapproved certifications on a given user ID.",
            command: &[
                "sq", "key", "approvals", "list",
                "--pending",
                "--email=alice@example.org",
                "--cert=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            ],
            hide: &[],
        }),
    ]
};
test_examples!(sq_key_approvals_list, LIST_EXAMPLES);

#[derive(Debug, Args)]
#[clap(
    name = "list",
    about = "Lists third-party certifications and their approval status",
    long_about = "\
Lists third-party certifications and their approval status

To prevent certificate flooding attacks, modern key servers prevent \
uncontrolled distribution of third-party certifications on \
certificates.  To allow the key holder to control what information is \
distributed with their certificate, these key servers only distribute \
third-party certifications that the key holder has explicitly \
approved.
",
    after_help = LIST_EXAMPLES,
)]
pub struct ListCommand {
    #[command(flatten)]
    pub cert: CertDesignators<CertUserIDEmailFileArgs,
                              CertPrefix,
                              OneValue,
                              ApprovalsListDoc>,

    #[command(flatten)]
    pub userids: UserIDDesignators<
        userid_designator::PlainByArgs,
        userid_designator::OptionalValue>,

    #[clap(
        long = "pending",
        help = "List unapproved certifications",
    )]
    pub pending: bool,
}

/// Documentation for the cert designators for the key approvals list
/// command.
pub struct ApprovalsListDoc {}

impl AdditionalDocs for ApprovalsListDoc {
    fn help(arg: &'static str, help: &'static str) -> clap::builder::StyledStr {
        match arg {
            "file" =>
                "List the approvals on the certificate read from PATH"
                .into(),
            _ => {
                debug_assert!(help.starts_with("Use certificates"));
                help.replace("Use certificates",
                             "List the approvals on the certificate")
                    .into()
            },
        }
    }
}

const UPDATE_EXAMPLES: Actions = Actions {
    actions: &[
        Action::setup().command(&[
            "sq", "key", "import", "alice-secret.pgp",
        ]).build(),

        Action::setup().command(&[
            "sq", "key", "import", "bob-secret.pgp",
        ]).build(),

        Action::setup().command(&[
            "sq", "pki", "vouch", "add",
            "--certifier=511257EBBF077B7AEDAE5D093F68CB84CE537C9A",
            "--cert=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            "--email=alice@example.org",
        ]).build(),

        Action::setup().command(&[
            "sq", "pki", "link", "add",
            "--cert=511257EBBF077B7AEDAE5D093F68CB84CE537C9A",
            "--email=bob@example.org",
        ]).build(),

        Action::example().comment("\
Approve of all of the certifications on all of Alice's user IDs."
        ).command(&[
            "sq", "key", "approvals", "update",
            "--add-all",
            "--cert=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
        ]).build(),

        Action::example().comment("\
Approve of all of the certifications on all of Alice's user IDs made by Bob, \
discarding all prior approvals first."
        ).command(&[
            "sq", "key", "approvals", "update",
            "--remove-all",
            "--add-by=511257EBBF077B7AEDAE5D093F68CB84CE537C9A",
            "--cert=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
        ]).build(),

        Action::example().comment("\
Approve of all of the certifications on a specific user ID by certifiers that \
can be authenticated, discarding all prior approvals first."
        ).command(&[
            "sq", "key", "approvals", "update",
            "--remove-all",
            "--add-authenticated",
            "--cert=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            "--userid=Alice <alice@example.org>",
        ]).build(),

        Action::example().comment("\
Remove the approval of Bob's certification on all of Alice's user IDs."
        ).command(&[
            "sq", "key", "approvals", "update",
            "--remove-by=511257EBBF077B7AEDAE5D093F68CB84CE537C9A",
            "--cert=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
        ]).build(),
    ]
};
test_examples!(sq_key_approvals_update, UPDATE_EXAMPLES);

#[derive(Debug, Args)]
#[clap(
    name = "update",
    about = "Approves of third-party certifications allowing for their distribution",
    long_about = "\
Approves of third-party certifications allowing for their distribution

To prevent certificate flooding attacks, modern key servers prevent \
uncontrolled distribution of third-party certifications on \
certificates.  To allow the key holder to control what information is \
distributed with their certificate, these key servers only distribute \
third-party certifications that the key holder has explicitly \
approved.

By default, all user IDs are considered, but if at least one `--name`, \
`--email`, or `--userid` argument is given, only the matching user IDs \
are considered.

After the approvals have been changed, the certificate has to be \
distributed, e.g. by uploading it to a key server.
",
    after_help = UPDATE_EXAMPLES,
)]
#[clap(group(
    ArgGroup::new("action")
        .args(&[
            "remove_all",
            "remove_by",
            "add_all",
            "add_by",
            "add_authenticated",
        ])
        .required(true)
        .multiple(true)))]
pub struct UpdateCommand {
    #[command(flatten)]
    pub cert: CertDesignators<CertUserIDEmailFileArgs,
                              CertPrefix,
                              OneValueAndFileRequiresOutput,
                              ApprovalsListDoc>,

    #[command(flatten)]
    pub userids: UserIDDesignators<
        userid_designator::PlainByArgs,
        userid_designator::OptionalValue>,

    #[clap(
        long = "remove-all",
        help = "Remove all prior approvals",
        conflicts_with = "add_all",
        long_help = "\
Remove all prior approvals

By default, this command adds to the set of already approved
certifications.  If this flag is given, the existing approvals are
disregarded, and only the newly selected certifications are approved,
if any.
",
    )]
    pub remove_all: bool,

    #[clap(
        long = "remove-by",
        value_name = "FINGERPRINT|KEYID",
        help = "Remove all prior approvals of certifications by this certifier",
        conflicts_with = "remove_all",
    )]
    pub remove_by: Vec<KeyHandle>,

    #[clap(
        long = "add-all",
        help = "Approve of all pending certifications",
        conflicts_with_all = ["remove_all", "remove_by"],
    )]
    pub add_all: bool,

    #[clap(
        long = "add-by",
        value_name = "FINGERPRINT|KEYID",
        help = "Approve of all certifications by this certifier",
        conflicts_with = "add_all",
    )]
    pub add_by: Vec<KeyHandle>,

    #[clap(
        long = "add-authenticated",
        value_name = "AMOUNT",
        help = "Approve of all certifications by authenticated certifiers",
        long_help = "\
Approve of all certifications by authenticated certifiers

For all pending approvals, try to authenticate any user ID on the
certifier, and if any can be authenticated, approve of the certification.",
        conflicts_with = "add_all",
    )]
    pub add_authenticated: bool,

    #[clap(
        long,
        value_name = FileOrStdout::VALUE_NAME,
        help = "Write to the specified FILE",
        long_help = "\
Write to the specified FILE

If not specified, and the certificate was read from the certificate \
store, imports the modified certificate into the cert store.  If not \
specified, and the certificate was read from a file, writes the \
modified certificate to stdout.",
    )]
    pub output: Option<FileOrStdout>,
}
