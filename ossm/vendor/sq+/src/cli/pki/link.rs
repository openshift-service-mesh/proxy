//! Command-line parser for `sq pki link`.

use clap::{ArgGroup, Parser, Subcommand};

use crate::cli::examples::*;
use crate::cli::types::CertDesignators;
use crate::cli::types::cert_designator;
use crate::cli::types::UserIDDesignators;
use crate::cli::types::userid_designator;
use crate::cli::types::ExpirationArg;
use crate::cli::types::TrustAmount;
use crate::cli::types::cert_designator::*;

#[derive(Parser, Debug)]
#[clap(
    name = "link",
    about = "Manage authenticated certificate and User ID links",
    long_about =
"Manage authenticated certificate and User ID links

Linking a certificate and User ID is one way of making `sq` consider a \
binding to be authentic.  Another way is to use `sq pki vouch add` to \
certify the binding with an explicitly configured trust root.  The \
linking functionality is often easier to work with, and the \
information is private by default.

Authenticated bindings can be used to designate a certificate using a \
symbolic name.  For instance, using `sq encrypt`'s \
`--for-userid` and `--for-email` options, a user can \
designate a certificate using a User ID or an email address that is \
authenticated for that certificate.

`sq` also uses authenticated certificates to authenticate other \
data.  For instance, `sq verify` considers signatures made by an \
authenticated certificate to be authentic.

Users can create a link using `sq pki link add`.  That link can later be \
retracted using `sq pki link retract`.  A certificate can also be \
accepted as a trusted introducer by using `sq pki link authorize`.

`sq` implements linking using non-exportable certifications, and an \
implicit trust root.  An OpenPGP certificate directory, the default \
certificate store used by `sq`, includes a local trust root, which \
is stored under the `trust-root` special name.  When the user \
instructs `sq` to accept a binding, `sq` uses the local trust root \
to create a non-exportable certification, which it stores in the \
certificate directory.  In this way, operations that use the Web of \
Trust to authenticate a binding automatically use links.

When a user retracts a link, `sq` creates a new, non-exportable \
certification with zero trust.  This certification suppresses the \
previous link.
",
after_help = LINK_EXAMPLES,
    subcommand_required = true,
    arg_required_else_help = true,
    disable_help_subcommand = true,
)]
pub struct Command {
    #[clap(subcommand)]
    pub subcommand: Subcommands,
}


const LINK_EXAMPLES: Actions = Actions {
    actions: &[
        Action::example().comment(
            "Link the certificate EB28F26E2739A4870ECC47726F0073F60FD0CBF0 \
             with the email address alice@example.org.",
        ).command(&[
            "sq", "pki", "link", "add",
            "--cert=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            "--email=alice@example.org",
        ]).build(),

        Action::example().comment(
            "Then, temporarily accept the certificate \
             EB28F26E2739A4870ECC47726F0073F60FD0CBF0 with all of \
             its self-signed user IDs for a week.",
        ).command(&[
            "sq", "pki", "link", "add",
            "--expiration=1w",
            "--cert=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            "--all",
        ]).build(),

        Action::example().comment(
            "Accept the certificate EB28F26E2739A4870ECC47726F0073F60FD0CBF0 \
with all of its self-signed user IDs as a trusted certification \
authority constrained to the domain example.org.  That is, the \
certificate is considered a trusted introducer for example.org.",
        ).command(&[
            "sq", "pki", "link", "authorize",
            "--domain=example.org",
            "--cert=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            "--all",
        ]).build(),

        Action::example().comment(
            "List all links.",
        ).command(&[
            "sq", "pki", "link", "list",
        ]).build(),

        Action::example().comment(
            "Retract the acceptance of certificate EB28F26E2739A4870ECC47726F0073F60FD0CBF0 \
and any associated user IDs.  This effectively invalidates all links.",
        ).command(&[
            "sq", "pki", "link", "retract",
            "--cert=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            "--all",
        ]).build(),
    ],
};
test_examples!(sq_pki_link, LINK_EXAMPLES);

#[derive(Debug, Subcommand)]
pub enum Subcommands {
    Add(AddCommand),
    Authorize(AuthorizeCommand),
    Retract(RetractCommand),
    List(ListCommand),
}

#[derive(Parser, Debug)]
#[clap(
    name = "add",
    about = "Link a certificate and a user ID",
    long_about =
"Link a certificate and a user ID

This causes `sq` to consider the certificate and user ID binding to be \
authentic.  You would do this if you are confident that a particular \
certificate should be associated with Alice, for example.  Note: this \
does not consider the certificate to be a trusted introducer; it only \
considers the binding to be authentic.  To authorize a certificate to \
be a trusted introducer use `sq pki link authorize`.

A link can be retracted using `sq pki link retract`.

This command is similar to `sq pki vouch add`, but the certifications it \
makes are done using the certificate directory's trust root, not an \
arbitrary key.  Further, the certificates are marked as \
non-exportable.  The former makes it easier to manage certifications, \
especially when the user's certification key is offline.  And the \
latter improves the user's privacy, by reducing the chance that parts \
of the user's social graph is leaked when a certificate is shared.

By default a link never expires.  This can be overridden using \
`--expiration` argument.

`sq pki link add` respects the reference time set by the top-level \
`--time` argument. It sets the link's creation time to the reference \
time.
",
    after_help = ADD_EXAMPLES,
)]
#[clap(group(ArgGroup::new("expiration-group")
             .args(&["expiration", "temporary"])))]
pub struct AddCommand {
    #[command(flatten)]
    pub cert: CertDesignators<
        cert_designator::CertSpecialArgs,
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
        long = "temporary",
        conflicts_with_all = &[ "amount" ],
        help = "Temporarily accepts the binding",
        long_help =
            "Temporarily accepts the binding

Creates a fully \
trust link between a certificate and one or more \
User IDs for a week.  After that, the link is \
automatically downgraded to a partially trusted link \
(trust = 40).",
    )]
    pub temporary: bool,
    #[command(flatten)]
    pub expiration: ExpirationArg,


    #[clap(
        long = "recreate",
        help = "Recreate signature even if the parameters did not change",
        long_help = "\
Recreate signature even if the parameters did not change

If the link parameters did not change, and thus creating a signature \
should not be necessary, we omit the operation.  This flag can be given \
to force the signature to be re-created anyway.",
    )]
    pub recreate: bool,

    #[command(flatten)]
    pub signature_notations: crate::cli::types::SignatureNotationsArg,
}

const ADD_EXAMPLES: Actions = Actions {
    actions: &[
        Action::example().comment(
            "Link the certificate EB28F26E2739A4870ECC47726F0073F60FD0CBF0 \
with the email address alice@example.org.",
        ).command(&[
            "sq", "pki", "link", "add",
            "--cert=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            "--email=alice@example.org",
        ]).build(),

        Action::example().comment(
            "First, examine the certificate EB28F26E2739A4870ECC47726F0073F60FD0CBF0.",
        ).command(&[
            "sq", "inspect",
            "--cert=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
        ]).build(),

        Action::example().comment(
            "Then, temporarily accept the certificate \
EB28F26E2739A4870ECC47726F0073F60FD0CBF0 with all of its self-signed \
user IDs for a week.",
        ).command(&[
            "sq", "pki", "link", "add",
            "--expiration=1w",
            "--cert=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            "--all",
        ]).build(),

        Action::example().comment(
            "Once satisfied, permanently accept the certificate \
EB28F26E2739A4870ECC47726F0073F60FD0CBF0 with all of its self-signed \
user IDs.",
        ).command(&[
            "sq", "pki", "link", "add",
            "--cert=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            "--all",
        ]).build(),
    ],
};
test_examples!(sq_pki_link_add, ADD_EXAMPLES);

#[derive(Parser, Debug)]
#[clap(
    name = "authorize",
    about = "Make a certificate a trusted introducer",
    long_about = "\
Make a certificate a trusted introducer

This causes `sq` to consider the certificate to be a be a trusted \
introducer.  Trusted introducer is another word for certification \
authority (CA).  When you link a trusted introducer, you consider \
certifications made by the trusted introducer to be valid.  A trusted \
introducer can also designate further trusted introducers.

As is, a trusted introducer has a lot of power.  This power can be \
limited in several ways.

  - The ability to specify further introducers can be constrained \
using the `--depth` parameter.

  - The degree to which an introducer is trusted can be changed using \
the `--amount` parameter.

  - The user IDs that an introducer can certify can be constrained by \
domain using the `--domain` parameter or a regular expression using \
the `--regex` parameter.

These mechanisms allow you to say that you are willing to rely on the \
CA for example.org, but only for user IDs that have an email address \
for example.org, for instance.

A link can be retracted using `sq pki link retract`.

This command is similar to `sq pki vouch authorize`, but the certifications \
it makes are done using the certificate directory's trust root, not an \
arbitrary key.  Further, the certificates are marked as \
non-exportable.  The former makes it easier to manage certifications, \
especially when your certification key is offline.  And the latter \
improves your privacy, by reducing the chance that parts of your \
social graph are leaked when a certificate is shared.

By default a link never expires.  Using the `--expiration` argument \
specific validity periods may be defined.  It allows for providing a \
point in time for validity to end or a validity duration.

`sq pki link authorize` respects the reference time set by the \
top-level `--time` argument. It sets the link's creation time to the \
reference time.
",
    after_help = AUTHORIZE_EXAMPLES,
)]
#[clap(group(ArgGroup::new("constraint").args(&["regex", "domain", "unconstrained"]).required(true).multiple(true)))]
pub struct AuthorizeCommand {
    #[command(flatten)]
    pub cert: CertDesignators<
        cert_designator::CertSpecialArgs,
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
        default_value = "255",
        help = "Set the trust depth",
        long_help = "Set the trust depth

This is sometimes referred to as the trust level.  1 \
means CERTIFICATE is a trusted introducer (default), 2 means \
CERTIFICATE is a meta-trusted introducer and can authorize another \
trusted introducer, etc.",
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

    #[command(flatten)]
    pub expiration: ExpirationArg,

    #[clap(
        long = "recreate",
        help = "Recreate the signature even if the parameters did not change",
        long_help = "\
Recreate the signature even if the parameters did not change

If the link parameters did not change, and thus creating a signature \
should not be necessary, we omit the operation.  This flag can be given \
to force the signature to be recreated anyway.",
    )]
    pub recreate: bool,

    #[command(flatten)]
    pub signature_notations: crate::cli::types::SignatureNotationsArg,
}

const AUTHORIZE_EXAMPLES: Actions = Actions {
    actions: &[
        Action::example().comment(
            "Add an unconstrained trusted introducer.",
        ).command(&[
            "sq", "pki", "link", "authorize",
            "--unconstrained",
            "--cert=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            "--all",
        ]).build(),

        Action::example().comment(
            "Add a trusted introducer for example.org and example.com.",
        ).command(&[
            "sq", "pki", "link", "authorize",
            "--domain=example.org",
            "--domain=example.com",
            "--cert=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            "--all",
        ]).build(),

        Action::example().comment(
            "Add a partially trusted introducer.",
        ).command(&[
            "sq", "pki", "link", "authorize",
            "--unconstrained",
            "--amount=60",
            "--cert=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            "--all",
        ]).build(),
    ],
};
test_examples!(sq_pki_link_authorize, AUTHORIZE_EXAMPLES);

#[derive(Parser, Debug)]
#[clap(
    name = "retract",
    about = "Retract links",
    long_about =
"Retract links

This command retracts links that were previously created using `sq \
pki link add` or `sq pki link authorize`.  See that subcommand's \
documentation for more details. \
Note: this is called `retract` and not `remove`, because the \
certifications are not removed.  Instead a new certification is added, \
which says that the binding has not been authenticated.

`sq pki link retract` respects the reference time set by the top-level \
`--time` argument.  This causes a link to be retracted as of a \
particular time instead of the current time.
",
    after_help = RETRACT_EXAMPLES,
)]
pub struct RetractCommand {
    #[command(flatten)]
    pub signature_notations: crate::cli::types::SignatureNotationsArg,

    #[clap(
        long = "recreate",
        help = "Recreate signature even if the parameters did not change",
        long_help = "\
Recreate signature even if the parameters did not change

If the link parameters did not change, and thus creating a signature \
should not be necessary, we omit the operation.  This flag can be given \
to force the signature to be re-created anyway.",
    )]
    pub recreate: bool,

    #[command(flatten)]
    pub cert: CertDesignators<
        cert_designator::CertSpecialArgs,
        cert_designator::CertPrefix,
        cert_designator::OneValue>,

    #[command(flatten)]
    pub userids: UserIDDesignators<
        userid_designator::AllPlainAddAndByArgs,
        userid_designator::AllMatchesNonSelfSignedNoLinting>,
}

const RETRACT_EXAMPLES: Actions = Actions {
    actions: &[
        Action::example().comment(
            "Link the certificate EB28F26E2739A4870ECC47726F0073F60FD0CBF0 \
             with the email address alice@example.org."
        ).command(&[
            "sq", "pki", "link", "add",
            "--cert=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            "--add-email=alice@example.org",
        ]).build(),

        Action::example().comment(
            "Retract the acceptance of certificate EB28F26E2739A4870ECC47726F0073F60FD0CBF0 \
and the email address alice@example.org.",
        ).command(&[
            "sq", "pki", "link", "retract",
            "--cert=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            "--email=alice@example.org",
        ]).build(),

        Action::example().comment(
            "Retract the acceptance of certificate EB28F26E2739A4870ECC47726F0073F60FD0CBF0 \
and any associated user IDs.  This effectively invalidates all links.",
        ).command(&[
            "sq", "pki", "link", "retract",
            "--cert=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            "--all",
        ]).build(),
    ],
};
test_examples!(sq_pki_link_retract, RETRACT_EXAMPLES);

#[derive(Parser, Debug)]
#[clap(
    name = "list",
    about = "List links",
    long_about =
"List links

This command lists all bindings that are linked or whose link has been \
retracted.

Returns a non-zero exit code if an explicitly designated certificate
was never linked.",
    after_help = LIST_EXAMPLES,
)]
pub struct ListCommand {
    #[command(flatten)]
    pub certs: CertDesignators<CertUserIDEmailDomainGrepArgs,
                               CertPrefix,
                               OptionalValue>,

    /// A pattern to select the bindings to authenticate
    ///
    /// The pattern is treated as a UTF-8 encoded string and a
    /// case insensitive substring search (using the current
    /// locale) is performed against each User ID.  If a User ID
    /// is not valid UTF-8, the binding is ignored.
    #[clap(
        conflicts_with_all = &["cert", "cert-userid", "cert-email",
                               "cert-domain", "cert-grep"],
    )]
    pub pattern: Option<String>,

    #[clap(
        long = "ca",
        required = false,
        help = "Only lists bindings linked as CAs",
        long_help = "Only lists bindings linked as CAs

That is, only list a link if its trust depth is greater than 0.",
    )]
    pub ca: bool,
}

const LIST_EXAMPLES: Actions = Actions {
    actions: &[
        Action::example().comment(
            "Link the certificate EB28F26E2739A4870ECC47726F0073F60FD0CBF0 \
with the email address alice@example.org.",
        ).command(&[
            "sq", "pki", "link", "add",
            "--cert=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            "--email=alice@example.org",
        ]).build(),

        Action::example().comment(
            "List all links.",
        ).command(&[
            "sq", "pki", "link", "list",
        ]).build(),

        Action::example().comment(
            "List links to certificates with an authenticated user ID \
             that contains an email address in the specified domain.",
        ).command(&[
            "sq", "pki", "link", "list",
            "--cert-domain=example.org",
        ]).build(),
    ],
};
test_examples!(sq_pki_link_list, LIST_EXAMPLES);
