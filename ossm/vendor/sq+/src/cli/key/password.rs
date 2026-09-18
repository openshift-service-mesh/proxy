//! Command-line parser for `sq key password`.

use std::path::PathBuf;

use clap::Args;

use crate::cli::types::*;
use crate::cli::examples::*;
use crate::cli::types::cert_designator::*;

#[derive(Debug, Args)]
#[clap(
    name = "password",
    about = "Change the password protecting secret key material",
    long_about = "\
Change the password protecting secret key material

Secret key material can be protected by a password.  This subcommand \
changes or clears the password.

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
    pub cert: CertDesignators<CertUserIDEmailFileArgs,
                              CertPrefix,
                              OneValueAndFileRequiresOutput,
                              KeyPasswordDoc>,

    #[clap(
        long = "new-password-file",
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
    )]
    pub output: Option<FileOrStdout>,
}

const EXAMPLES: Actions = Actions {
    actions: &[
        Action::setup().command(&[
            "sq", "key", "import", "alice-secret.pgp"
        ]).build(),

        Action::example().comment("\
Change the password for all of Alice's keys to the password in the \
specified file."
        ).command(&[
            "sq", "key", "password",
            "--new-password-file", "password-file.txt",
            "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0"
        ]).build(),

        Action::example().comment("\
Clear the password protection for all of Alice's keys."
        ).command(&[
                "sq", "key", "password",
                "--password-file", "password-file.txt",
                "--clear-password",
                "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0"
        ]).build(),
    ]
};
test_examples!(sq_key_password, EXAMPLES);

/// Documentation for the cert designators for the key password.
pub struct KeyPasswordDoc {}

impl AdditionalDocs for KeyPasswordDoc {
    fn help(arg: &'static str, help: &'static str) -> clap::builder::StyledStr {
        match arg {
            "file" =>
                "Change the password for the secret key material from the key \
                 read from PATH"
                .into(),
            _ => {
                debug_assert!(help.starts_with("Use certificates"));
                help.replace("Use certificates",
                             "Change the password for the secret key material \
                              from the key")
            },
        }.into()
    }
}
