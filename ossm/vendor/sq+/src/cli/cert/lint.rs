//! Command-line parser for `sq cert lint`.

use clap::Args;

use crate::cli::examples::*;
use crate::cli::types::ClapData;
use crate::cli::types::FileOrStdout;
use crate::cli::types::cert_designator::*;

/// Checks for and optionally repairs OpenPGP certificates that use
/// SHA-1.
#[derive(Debug, Args)]
#[clap(
    about = "Check certificates for issues",
    long_about = "Check certificates for issues

`sq cert lint` checks the supplied certificates for the following \
SHA-1-related issues:

  - Whether a certificate revocation uses SHA-1.

  - Whether the current self signature for a non-revoked User ID uses \
    SHA-1.

  - Whether the current subkey binding signature for a non-revoked, \
    live subkey uses SHA-1.

  - Whether a primary key binding signature (\"backsig\") for a \
    non-revoked, live subkey uses SHA-1.

Diagnostics are printed to stderr.  At the end, some statistics are \
shown.  This is useful when examining a keyring.  If `--fix` is \
specified and at least one issue could be fixed, the fixed \
certificates are printed to stdout.

This tool does not currently support smart cards.  But, if only the \
subkeys are on a smart card, this tool may still be able to partially \
repair the certificate.  In particular, it will be able to fix any \
issues with User ID self signatures and subkey binding signatures for \
encryption-capable subkeys, but it will not be able to generate new \
primary key binding signatures for any signing-capable subkeys.
",
    after_help = EXAMPLES,
)]
pub struct Command {
    /// Attempts to fix certificates, when possible.
    #[arg(long)]
    pub fix: bool,

    #[command(flatten)]
    pub certs: CertDesignators<FileCertUserIDEmailDomainGrepArgs,
                               CertPrefix,
                               OptionalValue>,

    #[clap(
        long,
        value_name = FileOrStdout::VALUE_NAME,
        help = "Write to the specified FILE",
        long_help = "Write to the specified FILE

If not specified, and the \
certificate was read from the certificate store, imports the \
modified certificate into the cert store.  If not specified, \
and the certificate was read from a file, writes the modified \
certificate to stdout.",
    )]
    pub output: Option<FileOrStdout>,
}

const EXAMPLES: Actions = Actions {
    actions: &[
        Action::setup().command(&[
            "sq", "keyring", "merge",
            "--output=certs.pgp",
            "bob.pgp", "romeo.pgp",
        ]).build(),

        Action::setup().command(&[
            "sq", "key", "import", "alice-secret.pgp",
        ]).build(),

        Action::example().comment(
            " Gather statistics on the certificates in a keyring."
        ).command (&[
            "sq", "cert", "lint",
            "--cert-file", "certs.pgp",
        ]).build(),

        Action::example().comment(
            "Fix a key with known problems."
        ).command (&[
            "sq", "key", "export",
            "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            "|", "sq", "cert", "lint", "--fix", "--cert-file=-",
            "|", "sq", "cert", "import"
        ]).build(),
    ],
};
test_examples!(sq_cert_lint, EXAMPLES);
