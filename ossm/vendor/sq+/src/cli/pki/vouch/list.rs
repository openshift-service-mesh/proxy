//! Command-line parser for `sq pki vouch list`.

use clap::Parser;

use crate::cli::types::CertDesignators;
use crate::cli::types::cert_designator;

use crate::cli::examples::*;

const LIST_EXAMPLES: Actions = Actions {
    actions: &[
        Action::setup().command(&[
            "sq", "key", "import",
            "alice-secret.pgp",
        ]).build(),

        // Alice certifies that Bob controls
        // 511257EBBF077B7AEDAE5D093F68CB84CE537C9A and
        // bob@example.org.
        Action::setup().command(&[
            "sq", "pki", "vouch", "add",
            "--certifier=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            "--cert=511257EBBF077B7AEDAE5D093F68CB84CE537C9A",
            "--email=bob@example.org",
        ]).build(),

        Action::example().comment(
            "List certifications made by Alice.",
        ).command(&[
            "sq", "pki", "vouch", "list",
            "--certifier=EB28F26E2739A4870ECC47726F0073F60FD0CBF0"
        ]).build(),

        Action::example().comment(
            "List certifications made by Alice for Bob's certificate.",
        ).command(&[
            "sq", "pki", "vouch", "list",
            "--certifier=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            "--cert=511257EBBF077B7AEDAE5D093F68CB84CE537C9A",
        ]).build(),
    ],
};
test_examples!(sq_pki_vouch_list, LIST_EXAMPLES);

#[derive(Parser, Debug)]
#[clap(
    name = "list",
    about = "List certifications",
    long_about = "\
List certifications

If the certifier argument is provided, then certifications made by the \
specified certificate are shown.  If the certificate argument is \
provided, then certifications of the specified certificate are shown. \
If both are provided, then certifications of the specified certificate \
made by the specified certifier are shown.

This command lists all of certifications, not just the active \
certification.

Because certifications are associated with the certificated \
certificate and not the certifier's certificate, this list is likely \
incomplete.

Stable since 1.2.0.
",
    after_help = LIST_EXAMPLES,
)]
pub struct Command {
    #[command(flatten)]
    pub certifier: CertDesignators<cert_designator::CertUserIDEmailFileSelfSpecialArgs,
                                   cert_designator::CertifierPrefix,
                                   cert_designator::OneOptionalValue>,

    #[command(flatten)]
    pub cert: CertDesignators<cert_designator::CertUserIDEmailFileArgs,
                              cert_designator::CertPrefix,
                              cert_designator::OneOptionalValue>,
}
