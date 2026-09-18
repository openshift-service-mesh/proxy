use std::path::PathBuf;

use clap::{ArgGroup, Args};

use crate::cli::KEY_ROTATE_RETIRE_IN_DURATION;
use crate::cli::KEY_ROTATE_RETIRE_IN_IN_DAYS;
use crate::cli::KEY_VALIDITY_DURATION;
use crate::cli::KEY_VALIDITY_IN_YEARS;
use crate::cli::config;
use crate::cli::types::ClapData;
use crate::cli::types::EncryptPurpose;
use crate::cli::types::Expiration;
use crate::cli::types::ExpirationArg;
use crate::cli::types::FileOrStdout;
use crate::cli::types::Profile;
use crate::cli::types::expiration::RetireInKind;
use crate::cli::types::CertDesignators;
use crate::cli::types::cert_designator;

use crate::cli::examples::*;
use crate::cli::key::CipherSuite;

#[derive(Debug, Args)]
#[clap(
    about = "Rotate a certificate",
    long_about = format!(
"Rotate a certificate

Generates a new certificate to replace an existing one.

The new certificate will have the same capabilities as the old \
certificate.  This can be overridden using the `--can-sign`, \
`--cannot-sign`, etc., arguments.  Note: the new certificate may have \
a different shape from the old certificate.  For instance, if the old \
certificate's primary key is marked as both certification and signing \
capable, the new certificate's primary key will be certification \
capable, and it will have a signing subkey.

By default the certificate expires after {} years.  This can be changed \
using the `--expiration` argument.

The new certificate will have the same self-signed user IDs as the old \
certificate.  Revoked user IDs are ignored.

The new certificate and the old certificate will cross certify each \
other as unconstrained trusted introducers.

The new certificate will be linked in the same way as the old \
certificate.  This can be overridden using the `--own-key`, or \
the `--shared-key` argument.

The new certificate will certify the same certificates as the old \
certificate.  That is, the old certificate's certifications will be \
replayed.  See `sq pki vouch replay` for more information.

A revocation certificate indicating that the old certificate is \
retired, and that the new certificate should be instead used will be \
issued.  By default, it will go into effect in {} days.  This can be \
changed or suppressed using the `--retire-in` argument.

When using `--output`, the new certificate as well as all of the \
other updated certificates are written to the specified file.

Stable since 1.2.0.
",
        KEY_VALIDITY_IN_YEARS,
        KEY_ROTATE_RETIRE_IN_IN_DAYS,
    ),
    after_help = ROTATE_EXAMPLES,
)]
#[clap(group(ArgGroup::new("cap-sign").args(&["can_sign", "cannot_sign"])))]
#[clap(group(ArgGroup::new("cap-authenticate").args(&["can_authenticate", "cannot_authenticate"])))]
#[clap(group(ArgGroup::new("cap-encrypt").args(&["can_encrypt", "cannot_encrypt"])))]
#[clap(mut_arg("expiration", |arg| {
    arg.default_value(Expiration::from_duration(KEY_VALIDITY_DURATION))
}))]
#[clap(mut_arg("retire-in", |arg| {
    arg.default_value(Expiration::from_duration(KEY_ROTATE_RETIRE_IN_DURATION))
}))]
pub struct Command {
    #[command(flatten)]
    pub cert: CertDesignators<cert_designator::CertUserIDEmailFileArgs,
                              cert_designator::CertPrefix,
                              cert_designator::OneValueAndFileRequiresOutput>,

    #[clap(
        long = "own-key",
        help = "Mark the key as one's own key",
        long_help = "Mark the key as one's own key

The newly generated key with all of its user IDs will be marked as \
authenticated and as a fully trusted introducer.",
    )]
    pub own_key: bool,

    #[clap(
        long = "shared-key",
        help = "Mark the key as a shared key",
        long_help = "Mark the key as a shared key

The newly generated key with all of its user IDs will be marked as \
authenticated, but not as a trusted introducer.  Further, the key \
metadata will indicate that this is a shared key.

Use this option if you plan to share this key with other people.  \
Normally, you shouldn't share keys material.  An example of where you \
might want to do this is a shared mailbox."
    )]
    pub shared_key: bool,

    #[clap(
        long = "cipher-suite",
        value_name = "CIPHER-SUITE",
        default_value_t = Default::default(),
        help = "Select the cryptographic algorithms for the key",
        long_help = config::augment_help(
            "key.generate.cipher-suite",
            "Select the cryptographic algorithms for the key"),
        value_enum,
    )]
    pub cipher_suite: CipherSuite,

    /// Workaround for https://github.com/clap-rs/clap/issues/3846
    #[clap(skip)]
    pub cipher_suite_source: Option<clap::parser::ValueSource>,

    #[clap(
        long = "profile",
        value_name = "PROFILE",
        default_value_t = Default::default(),
        help = "Select the OpenPGP standard for the key",
        long_help = config::augment_help(
            "key.generate.profile",
            "Select the OpenPGP standard for the key

As OpenPGP evolves, new versions will become available.  This option \
selects the version of OpenPGP to use for the newly generated key.

Currently, sq supports only one version: RFC4880.  Consequently, this \
is the default.  However, there is already a newer version of the \
standard: RFC9580.  And, the default will change in a future version of \
sq."),
        value_enum,
    )]
    pub profile: Profile,

    /// Workaround for https://github.com/clap-rs/clap/issues/3846
    #[clap(skip)]
    pub profile_source: Option<clap::parser::ValueSource>,

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
        long = "without-password",
        help = "Don't protect the secret key material with a password",
    )]
    pub without_password: bool,

    #[command(flatten)]
    pub expiration: ExpirationArg,

    #[command(flatten)]
    pub retire_in: ExpirationArg<RetireInKind>,

    #[clap(
        long = "can-sign",
        help ="Add a signing-capable subkey",
    )]
    pub can_sign: bool,

    #[clap(
        long = "cannot-sign",
        help = "Don't add a signing-capable subkey",
    )]
    pub cannot_sign: bool,

    #[clap(
        long = "can-authenticate",
        help = "Add an authentication-capable subkey",
    )]
    pub can_authenticate: bool,

    #[clap(
        long = "cannot-authenticate",
        help = "Don't add an authentication-capable subkey",
    )]
    pub cannot_authenticate: bool,

    #[clap(
        long = "can-encrypt",
        value_name = "PURPOSE",
        help = "Add an encryption-capable subkey",
        long_help = "\
Add an encryption-capable subkey

Encryption-capable subkeys can be marked as suitable for transport \
encryption, storage encryption, or both, i.e., universal.",
        value_enum,
    )]
    pub can_encrypt: Option<EncryptPurpose>,

    #[clap(
        long = "cannot-encrypt",
        help = "Don't add an encryption-capable subkey",
    )]
    pub cannot_encrypt: bool,

    #[clap(
        long,
        value_name = FileOrStdout::VALUE_NAME,
        help = "Write the key to the specified file",
        long_help = "\
Write the key to the specified file

When not specified, the key is saved on the key store.",
        requires = "rev_cert",
    )]
    pub output: Option<FileOrStdout>,

    #[clap(
        long = "rev-cert",
        value_name = "FILE",
        help = "Write the emergency revocation certificate to FILE",
        long_help = format!("\
Write the emergency revocation certificate to FILE

When the key is stored on the key store, the revocation certificate is \
stored in {} by default.

When `--output` is specified, the revocation certificate is written to \
the file specified by `--rev-cert`.

If `--output` is `-`, then this option must not also be `-`.",
            sequoia_directories::Home::default()
            .map(|home| {
                let p = home.data_dir(sequoia_directories::Component::Other(
                    "revocation-certificates".into()));
                let p = p.display().to_string();
                if let Some(home) = dirs::home_dir() {
                    let home = home.display().to_string();
                    if let Some(rest) = p.strip_prefix(&home) {
                        return format!("$HOME{}", rest);
                    }
                }
                p
            })
            .unwrap_or("<unknown>".to_string()))
    )]
    pub rev_cert: Option<FileOrStdout>
}

const ROTATE_EXAMPLES: Actions = Actions {
    actions: &[
        Action::setup().command(&[
            "sq", "key", "import", "alice-secret.pgp",
        ]).build(),
        Action::example().comment("\
Rotates Alice's certificate."
        ).command(&[
            "sq", "key", "rotate",
            "--without-password",
            "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
        ])
        .hide(&["--without-password"]).build(),
    ],
};
test_examples!(sq_key_rotate, ROTATE_EXAMPLES);
