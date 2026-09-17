//! Command-line parser for `sq pki vouch`.

pub mod authorize;
pub mod add;
pub mod list;
pub mod replay;

use clap::{Parser, Subcommand};

use crate::cli::examples::*;

/// Key for the help augmentation.
pub const CERTIFIER_SELF: &str = "pki.vouch.certifier-self";

/// Key for the help augmentation.
pub const CERTIFICATION_EXPIRATION: &str = "pki.vouch.expiration";

#[derive(Parser, Debug)]
#[clap(
    name = "vouch",
    about = "Manage certifications",
    long_about =
"Manage certifications

A vouch is a potentially public statement that something is true.  In \
OpenPGP there are two main types of statements that you can make: \
certifications, and authorizations.

You can assert that a certificate belongs to a particular entity. \
This says nothing about an entity's trustworthiness.  For instance, \
you might certify `bob@nsa.gov` for a given certificate.  This just \
means that you think the person behind the email address `bob@nsa.gov` \
really controls that certificate.  That's a useful statement to make \
even if you don't trust that person to act in your interest.

Alternatively you can say that you believe a certificate is a \
reasonable trusted introducer.  A trusted introducer is a third-party \
that you authorize to make introductions.  For instance, your bank \
might have a certification authority (CA).  If you verify the CA's \
fingerprint, you can authorize it to make certifications.  That means \
that sq will use those certifications almost as if you made them. \
This is convenient as now you can authenticate any of the bank's \
employee.

Authorizing a trusted introducer gives the trusted introducer a lot of \
power.  You can constrain the amount of power that you give it by \
saying that it is only authorized to certify user IDs that have an \
email address in one or more domains, for instance.  In this way, you \
can take advantage of the places where your and a CA's interests are \
aligned, and protect yourself from potentially malicious actions.  For \
example, you could authorize your bank's CA to certify user IDs that \
have an email address in `bank.com`.  sq will then ignore any other \
certifications made by the CA.
",
after_help = VOUCH_EXAMPLES,
    subcommand_required = true,
    arg_required_else_help = true,
    disable_help_subcommand = true,
)]
pub struct Command {
    #[clap(subcommand)]
    pub subcommand: Subcommands,
}


const VOUCH_EXAMPLES: Actions = Actions {
    actions: &[
        Action::setup().command(&[
            "sq", "key", "import", "ca-secret.pgp",
        ]).build(),

        Action::setup().command(&[
            "sq", "cert", "import", "alice-secret.pgp",
        ]).build(),

        Action::example().comment(
            "Certify EB28F26E2739A4870ECC47726F0073F60FD0CBF0 \
             for alice@example.org.",
        ).command(&[
            "sq", "pki", "vouch", "add",
            "--certifier=E7FC51AD886BBB5C4F44C3D7A9DA14F3E740F63F",
            "--cert=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            "--email=alice@example.org",
        ]).build(),

        Action::example().comment(
            "Certify EB28F26E2739A4870ECC47726F0073F60FD0CBF0 \
             as a trusted introducer for example.org.",
        ).command(&[
            "sq", "pki", "vouch", "authorize",
            "--certifier=E7FC51AD886BBB5C4F44C3D7A9DA14F3E740F63F",
            "--cert=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            "--domain=example.org",
            "--all",
        ]).build(),
    ],
};
test_examples!(sq_pki_vouch, VOUCH_EXAMPLES);

#[derive(Debug, Subcommand)]
pub enum Subcommands {
    Add(add::Command),
    Authorize(authorize::Command),
    List(list::Command),
    Replay(replay::Command),
}
