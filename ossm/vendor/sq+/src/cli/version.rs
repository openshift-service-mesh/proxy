//! Command-line parser for `sq inspect`.

use clap::Parser;

#[derive(Parser, Debug)]
#[clap(
    name = "version",
    about = "Detailed version and output version information",
    long_about =
"Detailed version and output version information

With no further options, this command lists the version of `sq`, the \
version of the underlying OpenPGP implementation `sequoia-openpgp`, \
and which cryptographic library is used.
",
)]
pub struct Command {
}
