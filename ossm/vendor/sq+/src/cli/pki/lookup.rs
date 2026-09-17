//! Command-line parser for `sq pki lookup`.

use clap::Parser;

use crate::cli::examples;
use examples::Action;
use examples::Actions;

use super::CertificationNetworkArg;
use super::GossipArg;
use super::RequiredTrustAmountArg;
use super::ShowPathsArg;
use super::UnusableArg;

use crate::cli::types::userid_designator;
use crate::cli::types::UserIDDesignators;

/// Lookup the certificates associated with a User ID
///
/// Identifies authenticated bindings (User ID and certificate
/// pairs) where the User ID matches the specified User ID.
///
/// An error is return if no binding could be authenticated to the
/// specified level (by default: fully authenticated, i.e., a trust
/// amount of 120).
///
/// If a binding could be partially authenticated (i.e., its trust
/// amount is greater than 0), then the binding is displayed, even
/// if the trust is below the specified threshold.
#[derive(Parser, Debug)]
#[clap(
    name = "lookup",
    after_help = EXAMPLES,
)]
pub struct Command {
    #[command(flatten)]
    pub userid: UserIDDesignators<
        userid_designator::PlainByArgs,
        userid_designator::OneValueNoLinting,
        Documentation>,

    #[command(flatten)]
    pub show_paths: ShowPathsArg,

    #[command(flatten)]
    pub gossip: GossipArg,

    #[command(flatten)]
    pub unusable: UnusableArg,

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
        match (typ, semantics) {
            (UserID, _) => {
                ("\
Find certificates that can be authenticated for the specified user ID",
                 Some("\
Find certificates that can be authenticated for the specified user ID

The specified user ID does not need to be self signed."))
            }
            (Email, _) => {
                ("\
Find certificates that can be authenticated for the specified email \
address",
                 Some("\
Find certificates that can be authenticated for the specified email \
address

A certificate is returned if a user ID with the specified email \
address can be authenticated for that certificate.

To search for a certificate with a user ID containing just \
the specified email address, use `--userid <EMAIL>`."))
            }
            (Name, _) => {
                ("\
Find certificates that can be authenticated for the specified display \
name",
                 Some("\
Find certificates that can be authenticated for the specified display \
name

A certificate is returned if a user ID with the specified display \
name can be authenticated for that certificate.

To search for a certificate with a user ID containing just \
the specified display name, use `--userid NAME`."))
            }
        }
    }
}

const EXAMPLES: Actions = Actions {
    actions: &[
        // Link Alice's certificate.
        Action::setup().command(&[
            "sq", "pki", "link", "add",
            "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            "--all",
        ]).build(),

        Action::example().comment(
            "Lookup certificates that can be authenticated for the given user ID.",
        ).command(&[
            "sq", "pki", "lookup",
            "--userid", "Alice <alice@example.org>"
        ]).build(),

        Action::example().comment(
            "Lookup certificates that have a user ID with the specified email \
address, and that user ID can be authenticated.",
        ).command(&[
            "sq", "pki", "lookup",
            "--email", "alice@example.org",
        ]).build(),
    ],
};
test_examples!(sq_pki_lookup, EXAMPLES);
