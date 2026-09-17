use clap::{ValueEnum, ArgGroup, Args, Subcommand};

use sequoia_openpgp as openpgp;
use openpgp::packet::UserID;
use openpgp::types::ReasonForRevocation;

use crate::cli::types::ClapData;
use crate::cli::types::FileOrCertStore;
use crate::cli::types::FileOrStdout;
use crate::cli::types::UserIDDesignators;
use crate::cli::types::cert_designator::*;
use crate::cli::types::userid_designator;

use crate::cli::examples;
use examples::Action;
use examples::Actions;

#[derive(Debug, Subcommand)]
#[clap(
    name = "userid",
    about = "Manage User IDs",
    long_about =
"Manage User IDs

Add User IDs to a key, or revoke them.
",
    subcommand_required = true,
    arg_required_else_help = true,
    disable_help_subcommand = true,
)]
pub enum Command {
    Add(AddCommand),
    Revoke(RevokeCommand),
}

const USERID_ADD_EXAMPLES: Actions = Actions {
    actions: &[
        Action::setup().command(&[
            "sq", "key", "import", "alice-secret.pgp"
        ]).build(),

        Action::example().comment("
Add a new user ID to Alice's key."
        ).command(&[
            "sq", "key", "userid", "add",
            "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            "--name", "Alice",
            "--email", "alice@work.example.com",
        ]).build(),
    ]
};
test_examples!(sq_key_userid_add, USERID_ADD_EXAMPLES);

#[derive(Debug, Args)]
#[clap(
    about = "Add a user ID",
    long_about =
"Add a user ID

A user ID can contain a name, like `Juliet`, or an email address, like \
`<juliet@example.org>`.  Historically, a name and an email address were \
usually combined as a single user ID, like `Juliet <juliet@example.org>`. \
However, user IDs that include different information such as name and \
email address are more difficult to reason about, so using distinct \
user IDs for name and email address is preferred nowadays.

`sq key userid add` respects the reference time set by the top-level \
`--time` argument.  It sets the creation time of the user ID's \
binding signature to the specified time.
",
    after_help = USERID_ADD_EXAMPLES,
)]
#[clap(group(ArgGroup::new("new-userid").args(&["names", "emails", "userid"]).required(true).multiple(true)))]
pub struct AddCommand {
    #[command(flatten)]
    pub cert: CertDesignators<CertUserIDEmailFileArgs,
                              CertPrefix,
                              OneValueAndFileRequiresOutput,
                              UserIDAddDoc>,

    #[clap(
        long = "name",
        value_name = "NAME",
        help = "Add a name as user ID to the key"
    )]
    pub names: Vec<String>,

    #[clap(
        long = "email",
        value_name = "ADDRESS",
        help = "Add an email address as user ID to the key"
    )]
    pub emails: Vec<String>,

    #[clap(
        long,
        value_name = "USERID",
        help = "Add a user ID to the key",
        long_help = "\
Add a user ID to the key

This user ID can combine name and email address, can optionally
contain a comment, or even be free-form if
`--allow-non-canonical-userids` is given.  However, user IDs that
include different information such as name and email address are more
difficult to reason about, so using distinct user IDs for name and
email address is preferred nowadays.

In doubt, prefer `--name` and `--email`.
",
    )]
    pub userid: Vec<UserID>,

    #[clap(
        long,
        help = "Don't reject user IDs that are not in canonical form",
        long_help = "\
Don't reject user IDs that are not in canonical form

Canonical user IDs are of the form `Name (Comment) \
<localpart@example.org>`.",
    )]
    pub allow_non_canonical_userids: bool,
    #[clap(
        long,
        value_name = FileOrCertStore::VALUE_NAME,
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

/// Documentation for the cert designators for the key userid add.
pub struct UserIDAddDoc {}

impl AdditionalDocs for UserIDAddDoc {
    fn help(arg: &'static str, help: &'static str) -> clap::builder::StyledStr {
        match arg {
            "file" =>
                "Add the user ID to the key \
                 read from PATH"
                .into(),
            _ => {
                debug_assert!(help.starts_with("Use certificates"));
                help.replace("Use certificates",
                             "Add the user ID to the key")
                    .into()
            },
        }
    }
}

const USERID_REVOKE_EXAMPLES: Actions = Actions {
    actions: &[
        Action::setup().command(&[
            "sq", "key", "import", "alice-secret.pgp"
        ]).build(),

        Action::example().comment("\
Retire a user ID on Alice's key."
        ).command(&[
            "sq", "key", "userid", "revoke",
            "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            "--userid", "Alice <alice@example.org>",
            "--reason", "retired",
            "--message", "No longer at example.org.",
        ]).build(),
    ]
};
test_examples!(sq_key_userid_revoke, USERID_REVOKE_EXAMPLES);

#[derive(Debug, Args)]
#[clap(
    about = "Revoke a user ID",
    long_about = "\
Revoke a user ID

Creates a revocation certificate for a user ID.

If `--revoker` or `--revoker-file` is provided, then that key is used \
to create the revocation certificate.  If that key is different from \
the certificate that is being revoked, this results in a third-party \
revocation.  This is normally only useful if the owner of the \
certificate designated the key to be a designated revoker.

To revoke a user ID, the certificate must be valid under the current \
policy.  If the certificate is not valid under the current policy, \
consider revoking the whole certificate, or fixing it using `sq cert \
lint` after verifying the certificate's integrity.  If the certificate \
is valid under the current policy, but the user ID you want to revoke \
isn't, you can still revoke the user ID using `--add-userid`.

`sq key userid revoke` respects the reference time set by the top-level \
`--time` argument.  When set, it uses the specified time instead of \
the current time when determining what keys are valid, and it sets \
the revocation certificate's creation time to the reference time \
instead of the current time.
",
    after_help = USERID_REVOKE_EXAMPLES,
)]
pub struct RevokeCommand {
    #[command(flatten)]
    pub cert: CertDesignators<CertUserIDEmailFileArgs,
                              CertPrefix,
                              OneValueAndFileRequiresOutput,
                              UserIDRevokeCertDoc>,

    #[command(flatten)]
    pub revoker: CertDesignators<CertUserIDEmailFileArgs,
                                 RevokerPrefix,
                                 OneOptionalValue,
                                 UserIDRevokeRevokerDoc>,

    #[command(flatten)]
    pub userids: UserIDDesignators<
        userid_designator::ExactByAndAddArgs,
        userid_designator::OneValue>,

    #[clap(
        long,
        value_enum,
        value_name = "REASON",
        required = true,
        help = "The reason for the revocation",
        long_help = "\
The reason for the revocation

If the reason happened in the past, you should specify that using the \
`--time` argument.  This allows OpenPGP implementations to more \
accurately reason about artifacts whose validity depends on the validity \
of the user ID."
    )]
    pub reason: UserIDReasonForRevocation,

    #[clap(
        long,
        value_name = "MESSAGE",
        required = true,
        help = "A short, explanatory text",
        long_help = "\
A short, explanatory text

The text is shown to a viewer of the revocation certificate, and \
explains why the certificate has been revoked.  For instance, if Alice \
has left the organization, it might say who to contact instead.",
    )]
    pub message: String,

    #[command(flatten)]
    pub signature_notations: crate::cli::types::SignatureNotationsArg,

    #[clap(
        long,
        value_name = FileOrCertStore::VALUE_NAME,
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

/// Documentation for the cert designators for the key userid revoke.
pub struct UserIDRevokeCertDoc {}

impl AdditionalDocs for UserIDRevokeCertDoc {
    fn help(arg: &'static str, help: &'static str) -> clap::builder::StyledStr {
        match arg {
            "file" =>
                "Revoke the user ID from the key \
                 read from PATH"
                .into(),
            _ => {
                debug_assert!(help.starts_with("Use certificates"));
                help.replace("Use certificates",
                             "Revoke the user ID from the key")
                    .into()
            },
        }
    }
}

/// Documentation for the revoker designators for the key userid revoke revoker.
pub struct UserIDRevokeRevokerDoc {}

impl AdditionalDocs for UserIDRevokeRevokerDoc {
    fn help(_: &'static str, help: &'static str) -> clap::builder::StyledStr {
        format!("{} to create the revocation certificate",
                help.replace("certificates", "key")).into()
    }

    fn long_help(_: &'static str, help: &'static str) -> Option<clap::builder::StyledStr> {
        Some(format!("{} to create the revocation certificate

Sign the revocation certificate using the specified key.  By default, \
the certificate being revoked is used.  Using this option, it is \
possible to create a third-party revocation.",
                     help.replace("certificates", "key")).into())
    }
}

/// The revocation reason for a user ID
#[derive(ValueEnum, Clone, Debug)]
pub enum UserIDReasonForRevocation {
    /// The user ID is no longer valid.  This is appropriate when
    /// someone leaves an organisation, and the organisation does not
    /// have their secret key material.  For instance, if someone was
    /// part of Debian and retires, they would use this to indicate
    /// that a Debian-specific User ID is no longer valid.
    Retired,

    /// None of the other reasons apply.  OpenPGP implementations
    /// conservatively treat this type of revocation similar to a
    /// compromised key.
    Unspecified
}

impl From<UserIDReasonForRevocation> for ReasonForRevocation {
    fn from(rr: UserIDReasonForRevocation) -> Self {
        match rr {
            UserIDReasonForRevocation::Retired => ReasonForRevocation::UIDRetired,
            UserIDReasonForRevocation::Unspecified => ReasonForRevocation::Unspecified,
        }
    }
}
