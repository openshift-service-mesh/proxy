//! Command-line parser for `sq pki identify`.

use clap::Parser;

use crate::cli::examples;
use examples::Action;
use examples::Actions;

use crate::cli::types::cert_designator;
use crate::cli::types::CertDesignators;

use super::CertificationNetworkArg;
use super::GossipArg;
use super::RequiredTrustAmountArg;
use super::ShowPathsArg;
use super::UnusableArg;

/// Identify a certificate
///
/// Identify a certificate by finding authenticated bindings (User
/// ID and certificate pairs).
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
    name = "identify",
    after_help = EXAMPLES,
)]
pub struct Command {
    // Note: don't add --cert-file: the certificate needs to be merged
    // into the certificate store, and --cert-file doesn't do that.
    // Instead, the user should use --keyring FILE and --cert FPR.
    #[command(flatten)]
    pub cert: CertDesignators<
        cert_designator::CertArg,
        cert_designator::CertPrefix,
        cert_designator::OneValue>,

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

const EXAMPLES: Actions = Actions {
    actions: &[
        // Link Alice's certificate.
        Action::setup().command(&[
            "sq", "pki", "link", "add",
            "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            "--all",
        ]).build(),

        Action::example().comment(
            "Identify the user IDs that can be authenticated for the certificate.",
        ).command(&[
            "sq", "pki", "identify",
            "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
        ]).build(),

        Action::example().comment(
            "List all user IDs that have that have been certified by anyone.",
        ).command(&[
            "sq", "pki", "identify", "--gossip",
            "--cert", "511257EBBF077B7AEDAE5D093F68CB84CE537C9A",
        ]).build(),
    ],
};
test_examples!(sq_pki_identify, EXAMPLES);
