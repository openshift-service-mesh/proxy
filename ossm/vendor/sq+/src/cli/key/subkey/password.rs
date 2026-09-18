use std::path::PathBuf;

use clap::Args;

use crate::cli::examples;
use examples::Action;
use examples::Actions;

use crate::cli::types::CertDesignators;
use crate::cli::types::ClapData;
use crate::cli::types::FileOrStdout;
use crate::cli::types::KeyDesignators;
use crate::cli::types::cert_designator;
use crate::cli::types::key_designator;

pub struct CertAdditionalDocs {}

impl cert_designator::AdditionalDocs for CertAdditionalDocs {
    fn help(arg: &'static str, help: &'static str) -> clap::builder::StyledStr {
        match arg {
            "file" =>
                "Change the password for the secret key material of the \
                 specified (sub)keys from the key read from PATH"
                .into(),
            _ => {
                debug_assert!(help.starts_with("Use certificates"));
                help.replace("Use certificates",
                             "Change the password for the secret key material \
                              of the specified (sub)keys from the key")
                   .into()
            },
        }
    }
}

pub struct KeyAdditionalDocs {}

impl key_designator::AdditionalDocs for KeyAdditionalDocs {
    fn help(_arg: &'static str, _help: &'static str)
        -> clap::builder::StyledStr
    {
        "Change the password protecting the specified key's secret key \
         material".into()
    }
}

#[derive(Debug, Args)]
#[clap(
    name = "password",
    about = "Change the password protecting secret key material",
    long_about = "\
Change the password protecting secret key material

Secret key material can be protected by a password.  This subcommand \
changes or clears the password of one or more keys.

To strip the password either use `--clear` or supply a zero-length \
password when prompted for the new password.

If a key is password protected, and the correct password was not \
supplied using the `--password-file` argument, the user is \
prompted for the password.  Likewise, if the new password isn't \
provided, the user is prompted.
",
    after_help = EXAMPLES,
)]
pub struct Command {
    #[command(flatten)]
    pub cert: CertDesignators<
        cert_designator::CertUserIDEmailFileArgs,
        cert_designator::CertPrefix,
        cert_designator::OneValueAndFileRequiresOutput,
        CertAdditionalDocs>,

    #[command(flatten)]
    pub keys: KeyDesignators<
        key_designator::DefaultOptions,
        KeyAdditionalDocs>,

    #[clap(
        long,
        value_name = "PASSWORD_FILE",
        help = "\
File containing password to encrypt the secret key material",
        long_help = "\
File containing password to encrypt the secret key material

Note that the entire key file will be used as the password including \
any surrounding whitespace like a trailing newline."
    )]
    pub new_password_file: Option<PathBuf>,
    #[clap(
        long,
        help = "Clear the password protecting the secret key material",
    )]
    pub clear_password: bool,

    #[clap(
        help = FileOrStdout::HELP_OPTIONAL,
        long,
        value_name = FileOrStdout::VALUE_NAME,
        conflicts_with = "cert",
    )]
    pub output: Option<FileOrStdout>,
}

const EXAMPLES: Actions = Actions {
    actions: &[
        Action::setup().command(&[
            "sq", "key", "import", "alice-secret.pgp"
        ]).build(),

        Action::example().comment("\
Change the password for Alice's signing key to the password in the \
specified file."
        ).command(&[
            "sq", "key", "subkey", "password",
            "--new-password-file=password-file.txt",
            "--cert=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            "--key=42020B87D51877E5AF8D272124F3955B0B8DECC8",
        ]).build(),

        Action::example().comment("\
Clear the password protection for Alice's signing key."
        ).command(&[
                "sq", "key", "subkey", "password",
                "--password-file=password-file.txt",
                "--clear-password",
                "--cert=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
                "--key=42020B87D51877E5AF8D272124F3955B0B8DECC8",
        ]).build(),
    ]
};
test_examples!(sq_key_subkey_password, EXAMPLES);
