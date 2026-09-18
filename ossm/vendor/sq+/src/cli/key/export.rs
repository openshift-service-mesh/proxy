//! Command-line parser for `sq key list`.

use clap::Args;

use crate::cli::examples::*;
use crate::cli::types::*;
use crate::cli::types::cert_designator::*;

#[derive(Debug, Args)]
#[clap(
    about = "Export keys from the key store",
    long_about = "\
Export keys from the key store

Exports the secret key material associated with a certificate.  Note \
that even if secret key material is available, it may not be \
exportable.  For instance, secret key material stored on a hardware \
security module usually cannot be exported from the device.

Iterate over all of the specified certificates and export \
any keys (primary key and subkeys) with secret key material.  \
An error is returned if any specified certificate does not \
contain any secret key material.

If you only want to export a particular key and not all keys associate \
with a certificate, use `sq key subkey export`.
",
    after_help = EXAMPLES,
)]
pub struct Command {
    #[command(flatten)]
    pub certs: CertDesignators<CertUserIDEmailDomainGrepArgs,
                               CertPrefix,
                               NoOptions,
                               ExportKeyDoc>,

    #[clap(
        default_value_t = FileOrStdout::default(),
        help = FileOrStdout::HELP_OPTIONAL,
        long,
        value_name = FileOrStdout::VALUE_NAME,
    )]
    pub output: FileOrStdout,
}

const EXAMPLES: Actions = Actions {
    actions: &[
        Action::setup().command(&[
            "sq", "key", "import", "alice-secret.pgp",
        ]).build(),

        Action::setup().command(&[
            "sq", "pki", "link", "add",
            "--cert=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            "--userid=Alice <alice@example.org>",
        ]).build(),

        Action::example().comment("\
Export Alice's certificate with all available secret key material."
        ).command(&[
            "sq", "key", "export",
            "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
        ]).build(),

        Action::example().comment("\
Export Alice's certificate with all available secret key material \
identified by email address."
        ).command(&[
            "sq", "key", "export",
            "--cert-email", "alice@example.org",
        ]).build(),
    ]
};
test_examples!(sq_key_export, EXAMPLES);

/// Documentation for the cert designators for the key export.
pub struct ExportKeyDoc {}

impl AdditionalDocs for ExportKeyDoc {
    fn help(_arg: &'static str, help: &'static str) -> clap::builder::StyledStr {
        debug_assert!(help.starts_with("Use certificates"));
        help.replace("Use certificates", "Export keys").into()
    }
}
