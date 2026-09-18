use clap::Parser;

use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;

use crate::cli::examples;
use examples::Action;
use examples::Actions;

use crate::cli::types::UserIDDesignators;
use crate::cli::types::userid_designator;

use super::CertificationNetworkArg;
use super::RequiredTrustAmountArg;

/// Verify the specified path
///
/// A path is a sequence of certificates starting at the root, and
/// a User ID.  This function checks that each path segment has a
/// valid certification, which also satisfies any constraints
/// (trust amount, trust depth, regular expressions).
///
/// If a valid path is not found, then this subcommand also lints
/// the path.  In particular, it report if any certifications are
/// insufficient, e.g., not enough trust depth, or invalid, e.g.,
/// because they use SHA-1, but the use of SHA-1 has been
/// disabled.
#[derive(Parser, Debug)]
#[clap(
    name = "path",
    after_help = EXAMPLES,
)]
pub struct Command {
    #[clap(
        value_name = "FINGERPRINT|KEYID",
        required = true,
        num_args = 1..,
        help = "The path to authenticate",
        long_help = "\
The path to authenticate

A path consists of one or more certificates.  The first certificate is \
the root, and the last certificate is the one being authenticated for \
the specified user ID.
",
    )]
    pub path: Vec<KeyHandle>,

    #[command(flatten)]
    pub userids: UserIDDesignators<
        userid_designator::PlainAddAndByArgs,
        userid_designator::OneValueNoLinting,
        Documentation>,

    #[command(flatten)]
    pub certification_network: CertificationNetworkArg,

    #[command(flatten)]
    pub trust_amount: RequiredTrustAmountArg,
}

/// Documentation for the user ID designators.
#[derive(Debug, Clone)]
pub struct Documentation(());

impl userid_designator::Documentation for Documentation {
    fn help(typ: userid_designator::UserIDDesignatorType,
            _plain: bool,
            semantics: userid_designator::UserIDDesignatorSemantics)
        -> (&'static str, Option<&'static str>)
    {
        use userid_designator::UserIDDesignatorType::*;
        use userid_designator::UserIDDesignatorSemantics::*;
        match (typ, semantics) {
            (UserID, _) => {
                ("Authenticate the specified user ID",
                 Some("\
Authenticate the specified user ID

The specified user ID does not need to be self signed."))
            }
            (Email, Add | Exact) => {
                ("Authenticate the specified email address",
                 Some("\
Authenticate the specified email address

This checks whether it is possible to authenticate the user ID \
consisting of just specified email address.  The user ID does \
not need to be self signed."))
            }
            (Email, By) => {
                ("\
Authenticate the self-signed user ID with the specified email address",
                 Some("\
Authenticate the self-signed user ID with the specified email address

This checks whether it is possible to authenticate the self-signed \
user ID with the specified email address.

If the certificate is invalid or there is no self-signed user ID with \
the specified email address, uses a user ID with just the email \
address."))
            }
            (Name, _) => {
                ("Authenticate the specified display name",
                 Some("\
Authenticate the specified display name

This checks whether it is possible to authenticate a user ID with the \
specified display name.  The user IDs do not need to be self signed.  \
To authenticate a user ID containing just the specified display name, \
use `--userid NAME`."))
            }
        }
    }
}

const EXAMPLES: Actions = Actions {
    actions: &[
        Action::example().comment(
            "Verify that Alice ceritified a particular User ID for Bob's certificate.",
        ).command(&[
            "sq", "pki", "path",
            "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            "511257EBBF077B7AEDAE5D093F68CB84CE537C9A",
            "--userid", "Bob <bob@example.org>",
        ]).build(),
    ],
};
test_examples!(sq_pki_path, EXAMPLES);
