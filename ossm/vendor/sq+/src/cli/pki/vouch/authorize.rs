//! Command-line parser for `sq pki vouch authorize`.

use clap::ArgGroup;
use clap::Parser;

use crate::cli::THIRD_PARTY_CERTIFICATION_VALIDITY_IN_YEARS;

use crate::cli::types::ClapData;
use crate::cli::types::expiration;
use crate::cli::types::ExpirationArg;
use crate::cli::types::FileOrStdout;
use crate::cli::types::TrustAmount;
use crate::cli::types::UserIDDesignators;
use crate::cli::types::cert_designator::{self, *};
use crate::cli::types::userid_designator;

use crate::cli::examples::*;

const AUTHORIZE_EXAMPLES: Actions = Actions {
    actions: &[
        Action::setup().command(&[
            "sq", "key", "import",
            "alice-secret.pgp",
        ]).build(),

        Action::setup().command(&[
            "sq", "cert", "import",
            "ca-secret.pgp",
        ]).build(),

        Action::example().comment(
            "Certify that E7FC51AD886BBB5C4F44C3D7A9DA14F3E740F63F \
             is a trusted introducer for example.org and example.com.",
        ).command(&[
            "sq", "pki", "vouch", "authorize",
            "--certifier=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            "--cert=E7FC51AD886BBB5C4F44C3D7A9DA14F3E740F63F",
            "--domain=example.org",
            "--domain=example.com",
            "--all",
        ]).build(),
    ],
};
test_examples!(sq_pki_vouch_authorize, AUTHORIZE_EXAMPLES);

#[derive(Parser, Debug)]
#[clap(
    name = "authorize",
    about = "Mark a certificate as a trusted introducer",
    long_about = format!(
"Mark a certificate as a trusted introducer

Creates a certification that says that the issuer considers the \
certificate to be a trusted introducer.  Trusted introducer is another \
word for certification authority (CA).  When a user relies on a \
trusted introducer, the user considers certifications made by the \
trusted introducer to be valid.  A trusted introducer can also \
designate further trusted introducers.

As is, a trusted introducer has a lot of power.  This power can be \
limited in several ways.

  - The ability to specify further introducers can be constrained \
using the `--depth` parameter.

  - The degree to which an introducer is trusted can be changed using \
the `--amount` parameter.

  - The user IDs that an introducer can certify can be constrained by \
domain using the `--domain` parameter or a regular expression using \
the `--regex` parameter.

These mechanisms allow Alice to say that she is willing to rely on the \
CA for example.org, but only for user IDs that have an email address \
for example.org, for instance.

By default a delegation expires after {} years. Use the `--expiration` \
argument to override this.

This subcommand respects the reference time set by the top-level \
`--time` argument.  It sets the certification's creation time to the \
reference time.
",
        THIRD_PARTY_CERTIFICATION_VALIDITY_IN_YEARS,
    ),
    after_help = AUTHORIZE_EXAMPLES,
)]
#[clap(group(ArgGroup::new("constraint").args(&["regex", "domain", "unconstrained"]).required(true).multiple(true)))]
pub struct Command {
    #[command(flatten)]
    pub certifier: CertDesignators<CertUserIDEmailFileSelfArgs,
                                   CertifierPrefix,
                                   OneValue,
                                   CertifierDoc>,

    #[command(flatten)]
    pub cert: CertDesignators<
        cert_designator::CertFileArgs,
        cert_designator::CertPrefix,
        cert_designator::OneValue>,

    #[command(flatten)]
    pub userids: UserIDDesignators<
        userid_designator::AllExactByAndAddArgs>,

    #[clap(
        long = "amount",
        value_name = "AMOUNT",
        default_value = "full",
        help = "Set the amount of trust",
        long_help =
            "Set the amount of trust

Values between 1 and 120 are meaningful. \
120 means fully trusted.  Values less than 120 indicate the degree \
of trust.  60 is usually used for partially trusted.",
    )]
    pub amount: TrustAmount<u8>,

    #[clap(
        long = "depth",
        value_name = "TRUST_DEPTH",
        default_value = "1",
        help = "Set the trust depth",
        long_help =
            "Set the trust depth

This is sometimes referred to as the trust level.  \
1 means CERTIFICATE is a trusted introducer (default), 2 means \
CERTIFICATE is a meta-trusted introducer and can authorize \
another trusted introducer, etc.",
    )]
    pub depth: u8,

    #[clap(
        long = "domain",
        value_name = "DOMAIN",
        help = "Add a domain constraint to the introducer",
        long_help = "\
Add a domain constraint to the introducer

Add a domain to constrain what certifications are respected.  A \
certification made by the certificate is only respected if it is over \
a user ID with an email address in the specified domain.  Multiple \
domains may be specified.  In that case, one must match.",
    )]
    pub domain: Vec<String>,
    #[clap(
        long = "regex",
        value_name = "REGEX",
        help = "Add a regular expression to constrain the introducer",
        long_help = "\
Add a regular expression to constrain the introducer

Add a regular expression to constrain what certifications are \
respected.  A certification made by the certificate is only respected \
if it is over a user ID that matches one of the specified regular \
expression.  Multiple regular expressions may be specified.  In that \
case, at least one must match.",
    )]
    pub regex: Vec<String>,
    #[clap(
        long,
        conflicts_with = "regex",
        help = "Don't constrain the introducer",
        long_help = "\
Don't constrain the introducer

Normally an introducer is constrained so that only certain user IDs \
are respected, e.g., those that have an email address for a certain \
domain name.  This option authorizes an introducer without \
constraining it in this way.  Because this grants the introducer a lot \
of power, you have to opt in to this behavior explicitly.",
    )]
    pub unconstrained: bool,

    #[clap(
        long = "local",
        help = "Make the certification a local certification",
        long_help =
            "Make the certification a local certification

Normally, local certifications are not exported.",
    )]
    pub local: bool,
    #[clap(
        long = "non-revocable",
        help = "Mark the certification as being non-revocable",
        long_help =
            "Mark the certification as being non-revocable

That is, you cannot later revoke this \
certification.  This should normally only \
be used with an expiration.",
    )]
    pub non_revocable: bool,

    #[command(flatten)]
    pub expiration: ExpirationArg<expiration::CertificationKind>,

    /// Workaround for https://github.com/clap-rs/clap/issues/3846
    #[clap(skip)]
    pub expiration_source: Option<clap::parser::ValueSource>,

    #[command(flatten)]
    pub signature_notations: crate::cli::types::SignatureNotationsArg,

    #[clap(
        help = FileOrStdout::HELP_OPTIONAL,
        long,
        value_name = FileOrStdout::VALUE_NAME,
    )]
    pub output: Option<FileOrStdout>,
}
