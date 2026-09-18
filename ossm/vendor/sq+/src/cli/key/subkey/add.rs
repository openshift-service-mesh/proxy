use std::path::PathBuf;

use clap::Args;
use clap::ArgGroup;

use crate::cli::examples;
use examples::Action;
use examples::Actions;

use crate::cli::config;
use crate::cli::key::CipherSuite;
use crate::cli::types::CertDesignators;
use crate::cli::types::ClapData;
use crate::cli::types::EncryptPurpose;
use crate::cli::types::ExpirationArg;
use crate::cli::types::FileOrStdout;
use crate::cli::types::cert_designator;

pub struct AdditionalDocs {}

impl cert_designator::AdditionalDocs for AdditionalDocs {
    fn help(arg: &'static str, help: &'static str) -> clap::builder::StyledStr {
        match arg {
            "file" =>
                "Add a subkey to the key read from PATH"
                .into(),
            _ => {
                debug_assert!(help.starts_with("Use certificates"));
                help.replace("Use certificates",
                             "Add a subkey to the key")
                    .into()
            },
        }
    }
}

#[derive(Debug, Args)]
#[clap(
    about = "Add a new subkey to a certificate",
    long_about = "\
Add a new subkey to a certificate

A subkey has one or more capabilities.

`--can-sign` sets the signing capability, and means that the key may \
be used for signing. `--can-authenticate` sets the authentication \
capability, and means that the key may be used for authentication \
(e.g., as an SSH key).  `--can-certify` sets the certificate \
capability, and means that the key may be used to make third-party \
certifications.  These capabilities may be combined.

`--can-encrypt=storage` sets the storage encryption capability, and \
means that the key may be used for storage \
encryption. `--can-encrypt=transport` sets the transport encryption \
capability, and means that the key may be used for transport \
encryption.  `--can-encrypt=universal` sets both the storage and the \
transport encryption capability, and means that the key may be used \
for both storage and transport encryption.  The encryption \
capabilities must not be combined with the signing or authentication \
capability.

Normally, `sq` prompts the user for a password to use to encrypt the \
secret key material.  The password for the new subkey may be different \
from the other keys.  When using `--without-password`, `sq` doesn't \
prompt for a password, and doesn't password-protect the subkey.

By default a new subkey doesn't expire on its own.  However, its \
validity period is limited by that of the certificate.  Using the \
`--expiration` argument allows setting a different expiration time.

`sq key subkey add` respects the reference time set by the top-level \
`--time` argument.  It sets the creation time of the subkey to the specified \
time.
",
    after_help = EXAMPLES,
)]
#[clap(group(ArgGroup::new("authentication-group").args(&["can_authenticate", "can_encrypt"])))]
#[clap(group(ArgGroup::new("sign-group").args(&["can_sign", "can_encrypt"])))]
#[clap(group(ArgGroup::new("required-group").args(&["can_authenticate", "can_sign", "can_encrypt"]).required(true)))]
pub struct Command {
    #[command(flatten)]
    pub cert: CertDesignators<
        cert_designator::CertUserIDEmailFileArgs,
        cert_designator::CertPrefix,
        cert_designator::OneValueAndFileRequiresOutput,
        AdditionalDocs>,

    #[clap(
        long,
        value_name = "CIPHER-SUITE",
        default_value_t = CipherSuite::Cv25519,
        help = "Select the cryptographic algorithms for the subkey",
        long_help = config::augment_help(
            "key.generate.cipher-suite",
            "Select the cryptographic algorithms for the subkey"),
        value_enum,
    )]
    pub cipher_suite: CipherSuite,

    /// Workaround for https://github.com/clap-rs/clap/issues/3846
    #[clap(skip)]
    pub cipher_suite_source: Option<clap::parser::ValueSource>,

    #[command(flatten)]
    pub expiration: ExpirationArg,

    #[clap(
        long,
        help = "Add a signing-capable subkey",
    )]
    pub can_sign: bool,
    #[clap(
        long,
        help = "Add an authentication-capable subkey",
    )]
    pub can_authenticate: bool,
    #[clap(
        long,
        value_name = "PURPOSE",
        help = "Add an encryption-capable subkey [default: universal]",
        long_help = "\
Add an encryption-capable subkey [default: universal]

Encryption-capable subkeys can be marked as suitable for transport \
encryption, storage encryption, or both, i.e., universal.",
        value_enum,
    )]
    pub can_encrypt: Option<EncryptPurpose>,

    #[clap(
        long = "new-password-file",
        value_name = "PASSWORD_FILE",
        help = "\
File containing password to encrypt the secret key material",
        long_help = "\
File containing password to encrypt the secret key material

Note that the entire key file will be used as the password including \
any surrounding whitespace like a trailing newline.",
        conflicts_with = "without_password",
    )]
    pub new_password_file: Option<PathBuf>,

    #[clap(
        long,
        help = "Don't protect the subkey's secret key material with a password",
    )]
    pub without_password: bool,

    #[clap(
        long,
        value_name = FileOrStdout::VALUE_NAME,
        help = "Write to the specified FILE",
        long_help = "\
Write to the specified FILE

If not specified, and the certificate was read from the certificate \
store, imports the modified certificate into the key store.  If not \
specified, and the certificate was read from a file, writes the \
modified certificate to stdout.",
    )]
    pub output: Option<FileOrStdout>,
}

const EXAMPLES: Actions = Actions {
    actions: &[
        Action::setup().command(&[
            "sq", "key", "import", "alice-secret.pgp",
        ]).build(),

        Action::example().comment("\
Add a new signing-capable subkey to Alice's key."
        ).command(&[
            "sq", "key", "subkey", "add",
            "--without-password",
            "--can-sign",
            "--cert=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
        ])
        .hide(&["--without-password"]).build(),
    ]
};
test_examples!(sq_key_subkey_add, EXAMPLES);
