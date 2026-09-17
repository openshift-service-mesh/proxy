use clap::Args;
use clap::ArgGroup;

use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;

use crate::cli::examples;
use examples::Action;
use examples::Actions;

use crate::cli::types::CertDesignators;
use crate::cli::types::ClapData;
use crate::cli::types::EncryptPurpose;
use crate::cli::types::ExpirationArg;
use crate::cli::types::FileOrStdout;
use crate::cli::types::Time;
use crate::cli::types::cert_designator;

pub struct AdditionalDocs {}

impl cert_designator::AdditionalDocs for AdditionalDocs {
    fn help(arg: &'static str, help: &'static str) -> clap::builder::StyledStr {
        match arg {
            "file" =>
                "Add the specified subkeys to the key read from PATH"
                .into(),
            _ => {
                debug_assert!(help.starts_with("Use certificates"));
                help.replace("Use certificates",
                             "Add the specified subkeys on the key")
                    .into()
            },
        }
    }
}

#[derive(Debug, Args)]
#[clap(
    name = "bind",
    about = "Bind keys from one certificate to another",
    long_about = "\
Bind keys from one certificate to another

This command allows the user to attach a primary key or a subkey \
attached to one certificate to another certificate.  Say you want to \
transition to a new certificate, but have an authentication subkey on \
your current certificate that you want to keep because it allows access \
a server and updating its configuration is not feasible.  This command \
makes it easy to attach the subkey to the new certificate.

After the operation, the key is bound both to the old certificate and to \
the new one.  To remove secret key material from the old certificate, use \
`sq key subkey delete` or `sq key delete`, as appropriate.  To revoke the \
old subkey or key, use `sq key subkey revoke` or `sq key revoke`, \
respectively.
",
    after_help = EXAMPLES,
)]
#[clap(group(ArgGroup::new("cap-sign").args(&["can_sign", "cannot_sign"])))]
#[clap(group(ArgGroup::new("cap-authenticate").args(&["can_authenticate", "cannot_authenticate"])))]
#[clap(group(ArgGroup::new("cap-encrypt").args(&["can_encrypt", "cannot_encrypt"])))]
pub struct Command {
    #[command(flatten)]
    pub cert: CertDesignators<
        cert_designator::CertUserIDEmailFileArgs,
        cert_designator::CertPrefix,
        cert_designator::OneValueAndFileRequiresOutput,
        AdditionalDocs>,

    #[clap(
        long,
        value_name = "KEY",
        required(true),
        help = "Add the key or subkey KEY to the certificate",
    )]
    pub key: Vec<KeyHandle>,
    #[clap(
        long,
        allow_hyphen_values = true,
        value_name = "CREATION_TIME",
        help = "Make bound subkeys have the specified creation time",
        long_help = "\
Make bound subkeys have the specified creation time

Normally, the key's creation time is preserved.  The exception is if \
the key's creation time is the Unix epoch.  In that case, the current \
time is used.

This option allows setting the key's creation time to a specified value.  \
Note: changing a key's creation time also changes its fingerprint.  \
Changing the fingerprint will make it impossible to look up the key for \
the purpose of signature verification, for example.",
    )]
    pub creation_time: Option<Time>,
    #[clap(flatten)]
    pub expiration: ExpirationArg,
    #[clap(
        long,
        help = "Allow adopting keys from certificates \
            using broken cryptography",
    )]
    pub allow_broken_crypto: bool,

    #[clap(
        long = "can-sign",
        help ="Set the signing-capable flag",
    )]
    pub can_sign: bool,
    #[clap(
        long = "cannot-sign",
        help = "Don't set the signing-capable flag",
    )]
    pub cannot_sign: bool,
    #[clap(
        long = "can-authenticate",
        help = "Set the authentication-capable flag",
    )]
    pub can_authenticate: bool,
    #[clap(
        long = "cannot-authenticate",
        help = "Don't set the authentication-capable flag",
    )]
    pub cannot_authenticate: bool,
    #[clap(
        long = "can-encrypt",
        value_name = "PURPOSE",
        help = "Set the encryption-capable flag",
        long_help = "\
Set the encryption-capable flag

Encryption-capable subkeys can be marked as suitable for transport \
encryption, storage encryption, or both, i.e., universal.  [default: \
universal]",
        value_enum,
    )]
    pub can_encrypt: Option<EncryptPurpose>,
    #[clap(
        long = "cannot-encrypt",
        help = "Don't set the encryption-capable flag",
    )]
    pub cannot_encrypt: bool,

    #[clap(
        long,
        value_name = FileOrStdout::VALUE_NAME,
        help = "Write to the specified FILE",
        long_help = "\
Write to the specified FILE

If not specified, and the certificate was read from the certificate \
store, imports the modified certificate into the cert store.  If not \
specified, and the certificate was read from a file, writes the \
modified certificate to stdout.",
    )]
    pub output: Option<FileOrStdout>,
}

const EXAMPLES: Actions = Actions {
    actions: &[

        Action::setup().command(&[
            "sq", "key", "import",
            "alice-secret.pgp", "alice-new-secret.pgp",
        ]).build(),

        Action::example().comment("\
Bind Alice's old authentication subkey to Alice's new certificate."
        ).command(&[
            "sq", "key", "subkey", "bind",
            "--cert=C5999E8191BF7B503653BE958B1F7910D01F86E5",
            "--key=0D45C6A756A038670FDFD85CB1C82E8D27DB23A1",
        ]).build(),

        Action::example().comment("\
Bind a bare key to Alice's certificate.  A bare key is a public key \
without any components or signatures.  This simplifies working with raw \
keys, e.g., keys generated on an OpenPGP card, a TPM device, etc."
        ).command(&[
            "sq", "key", "subkey", "bind",
            "--keyring=bare.pgp",
            "--cert=C5999E8191BF7B503653BE958B1F7910D01F86E5",
            "--key=B321BA8F650CB16443E06826DBFA98A78CF6562F",
            "--can-encrypt=universal",
        ]).build(),
    ]
};
test_examples!(sq_key_bind, EXAMPLES);
