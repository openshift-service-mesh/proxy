//! Command-line parser for `sq cert list`.

use clap::Parser;

use crate::cli::examples::Action;
use crate::cli::examples::Actions;
use crate::cli::pki::CertificationNetworkArg;
use crate::cli::pki::GossipArg;
use crate::cli::pki::RequiredTrustAmountArg;
use crate::cli::pki::ShowPathsArg;
use crate::cli::pki::UnusableArg;
use crate::cli::types::cert_designator::*;

const EXAMPLES: Actions = Actions {
    actions: &[
        Action::setup().command(&[
            "sq", "pki", "link", "add",
            "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            "--all",
        ]).build(),

        Action::example().comment(
            "List all bindings for user IDs containing an email address from \
             example.org, and that can be authenticated."
        ).command (&[
            "sq", "cert", "list", "@example.org",
        ]).build(),

        Action::example().comment(
            "List all authenticated bindings for User IDs containing a specific email address."
        ).command (&[
            "sq", "cert", "list",
            "--cert-email=alice@example.org",
        ]).build(),

        Action::example().comment(
            "List all paths to certificates containing a specific email address."
        ).command (&[
            "sq", "cert", "list", "--gossip", "--show-paths",
            "--cert-email=alice@example.org",
        ]).build(),
    ]
};
test_examples!(sq_cert_list, EXAMPLES);

/// List certificates and user IDs
///
/// List certificates and user IDs that match a query, are usable, and
/// can be authenticated.  By default, bindings (certificate and user
/// ID pairs) must be fully authenticated.  If no certificates or
/// bindings match a query, then the command returns a non-zero exit
/// code.
///
/// If no queries are provided, then all bindings that are usable, and
/// can be authenticated are listed.  If there are no such bindings,
/// the command still succeeds.
///
/// By default, unusable certificates, i.e., those that are not valid
/// according to the policy, are revoked, or are not live, are
/// skipped.  Likewise, user ID self signatures and certifications
/// that are not valid according to the policy, and user IDs that are
/// revoked are skipped.
#[derive(Parser, Debug)]
#[clap(
    name = "list",
    after_help = EXAMPLES,
)]
pub struct Command {
    #[command(flatten)]
    pub certs: CertDesignators<CertUserIDEmailDomainGrepArgs,
                               CertPrefix,
                               OptionalValue,
                               ListCertDoc>,

    #[clap(
        value_name = "FINGERPRINT|KEYID|PATTERN",
        help = "List certs that match the pattern",
        long_help = "\
List certs that match the pattern

If the pattern appears to be a fingerprint or key ID, it is treated as \
if it were passed to `--cert`, which matches on the certificate's \
fingerprint.  Otherwise, it is treated as if it were passed to \
`--cert-grep`, which matches on user IDs.",
        conflicts_with_all = &["cert", "cert-userid", "cert-email",
                               "cert-domain", "cert-grep"],
    )]
    pub pattern: Option<String>,

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

/// Documentation for the cert designators for the cert list.
pub struct ListCertDoc {}

impl AdditionalDocs for ListCertDoc {
    fn help(arg: &'static str, _help: &'static str) -> clap::builder::StyledStr {
        match arg {
            "cert" => "\
List certificates with the specified fingerprint or key ID".into(),
            "userid" => "\
List bindings with the specified user ID".into(),
            "email" => "\
List bindings with user IDs that contain the specified email address".into(),
            "domain" => "\
List bindings with user IDs that contain an email address in the \
specified domain".into(),
            "grep" => "\
List bindings with a user ID that contains the pattern".into(),
            _ => unreachable!(),
        }
    }

    fn long_help(arg: &'static str, _help: &'static str)
        -> Option<clap::builder::StyledStr>
    {
        match arg {
            "cert" => Some(format!("\
{}

Note: fingerprints and key IDs are self-authenticating identifiers.  As \
such, a certificate with the specified fingerprint or key ID is \
considered authenticated; no user IDs have to be authenticated.",
                                    Self::help(arg, "")).into()),
            "userid" => Some(format!("\
{}

The user ID must match exactly.",
                                     Self::help(arg, "")).into()),
            "email" => Some(format!("\
{}

Email addresses are first normalized by doing puny-code normalization on \
the domain, and lower casing the local part in the so-called empty \
locale.",
                                    Self::help(arg, "")).into()),
            "domain" => Some(format!("\
{}

A user ID's domain is extracted from the email address, if any, and is \
normalized by doing puny-code normalization.",
                                    Self::help(arg, "")).into()),
            "grep" => Some(format!("\
{}

Performs a case-insensitive substring search.  Case-folding is done in \
the empty locale.",
                                    Self::help(arg, "")).into()),
            _ => {
                None
            }
        }
    }
}
