//! Command-line parser for `sq key list`.

use clap::Args;

use crate::cli::examples::*;
use crate::cli::types::cert_designator::*;

#[derive(Debug, Args)]
#[clap(
    about = "List keys managed by the key store",
    after_help = EXAMPLES,
)]
pub struct Command {
    #[command(flatten)]
    pub certs: CertDesignators<CertUserIDEmailDomainGrepArgs,
                               CertPrefix,
                               OptionalValue,
                               ListKeyDoc>,

    #[clap(
        value_name = "FINGERPRINT|KEYID|PATTERN",
        help = "A pattern to filter the displayed certificates",
        long_help = "\
A pattern to filter the displayed certificates

If the pattern appears to be a fingerprint or key ID, it is treated as \
if it were passed to `--cert`, and matches on the certificate's \
fingerprint.  Otherwise, it is treated as if it were passed via \
`--cert-grep`, and matches on user IDs.
",
        conflicts_with_all = &["cert", "cert-userid", "cert-email",
                               "cert-domain", "cert-grep"],
    )]
    pub pattern: Option<String>,
}

const EXAMPLES: Actions = Actions {
    actions: &[
        Action::setup().command(&[
            "sq", "key", "import", "alice-secret.pgp"
        ]).build(),

        Action::setup().command(&[
            "sq", "pki", "link", "add",
            "--cert=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            "--userid=Alice <alice@example.org>",
        ]).build(),

        Action::example().comment("\
List the keys managed by the keystore server."
        ).command(&[
            "sq", "key", "list",
        ]).build(),

        Action::example().comment("\
List the keys managed by the keystore server \
with a user ID in example.org."
        ).command(&[
            "sq", "key", "list",
            "--cert-domain=example.org",
        ]).build(),
    ]
};
test_examples!(sq_key_list, EXAMPLES);

/// Documentation for the cert designators for the key list.
pub struct ListKeyDoc {}

impl AdditionalDocs for ListKeyDoc {
    fn help(_: &'static str, help: &'static str) -> clap::builder::StyledStr {
        debug_assert!(help.starts_with("Use certificates"));
        help.replace("Use certificates", "List keys").into()
    }
}
