use clap::ArgGroup;
use clap::Parser;

use crate::cli::types::*;
use crate::cli::types::cert_designator::CertUserIDEmailDomainGrepArgs;
use crate::cli::types::cert_designator::CertPrefix;
use crate::cli::types::cert_designator::OptionalValue;
use crate::cli::examples::*;

const EXAMPLES: Actions = Actions {
    actions: &[
        Action::setup().command(&[
            "sq", "pki", "link", "add",
            "--cert=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            "--userid=Alice <alice@example.org>",
        ]).build(),

        Action::setup().command(&[
            "sq", "pki", "link", "add",
            "--cert=511257EBBF077B7AEDAE5D093F68CB84CE537C9A",
            "--userid=Bob <bob@example.org>",
        ]).build(),

        Action::example().comment(
            "Export certificates with a User ID containing the \
             email address."
        ).command(&[
            "sq", "cert", "export", "--cert-email=alice@example.org",
        ]).build(),

        Action::example().comment(
            "Export certificates that contain a User ID with *either* \
             (not both!) email address."
        ).command(&[
            "sq", "cert", "export",
            "--cert-email=alice@example.org",
            "--cert-email=bob@example.org",
        ]).build(),

        Action::example().comment(
            "Export all certificates."
        ).command(&[
            "sq", "cert", "export", "--all",
        ]).build(),
    ],
};

test_examples!(sq_cert_export, EXAMPLES);


#[derive(Parser, Debug)]
#[clap(
    name = "export",
    about = "Export certificates from the local certificate store",
    long_about =
"Export certificates from the local certificate store

If multiple predicates are specified a certificate is returned if \
at least one of them matches.

This does not check the authenticity of the certificates in anyway. \
Before using the certificates, be sure to validate and authenticate \
them.

When matching on subkeys or User IDs, the component must have a valid \
self signature according to the policy.

Fails if search criteria are specified and none of them matches any \
certificates.  Note: this means if the certificate store is empty and \
no search criteria are specified, then this will return success.
",
    after_help = EXAMPLES,
)]
#[clap(group(ArgGroup::new("some-designator")
             .args(&["cert", "cert-userid", "cert-email", "cert-domain", "cert-grep", "all"])
             .required(true)
             .multiple(true)))]
pub struct Command {
    #[clap(
        default_value_t = FileOrStdout::default(),
        help = FileOrStdout::HELP_OPTIONAL,
        long,
        value_name = FileOrStdout::VALUE_NAME,
    )]
    pub output: FileOrStdout,

    #[clap(
        long = "local",
        help = "Export local (non-exportable) signatures",
        long_help = "\
Export local (non-exportable) signatures

By default, non-exportable signatures are not emitted when exporting \
certificates, certificate components that are only bound by \
non-exportable signatures are not emitted, and certificates consisting \
of only non-exportable components are not emitted.

This flag enables exporting of non-exportable signatures, components, \
and certs.  This is useful for synchronization between ones devices, \
for example.",
    )]
    pub local: bool,

    #[clap(
        long,
        conflicts_with_all = [
            "cert", "cert-userid", "cert-email", "cert-domain", "cert-grep",
        ],
        help = "Export all certificates",
    )]
    pub all: bool,

    #[command(flatten)]
    pub certs: CertDesignators<CertUserIDEmailDomainGrepArgs,
                               CertPrefix,
                               OptionalValue>,
}
