//! Command-line parser for `sq cert`.

use clap::{Parser, Subcommand};

pub mod export;
pub mod import;
pub mod lint;
pub mod list;

#[derive(Parser, Debug)]
#[clap(
    name = "cert",
    about = "Manage certificates",
    long_about =
"Manage certificates

We use the term \"certificate\", or \"cert\" for short, to refer to \
OpenPGP keys that do not contain secrets.  This subcommand provides \
primitives to generate and otherwise manipulate certs.

Conversely, we use the term \"key\" to refer to OpenPGP keys that do \
contain secrets.  See `sq key` for operations on keys.
",
    subcommand_required = true,
    arg_required_else_help = true,
    disable_help_subcommand = true,
)]
pub struct Command {
    #[clap(subcommand)]
    pub subcommand: Subcommands,
}

#[derive(Debug, Subcommand)]
pub enum Subcommands {
    Import(import::Command),
    Export(export::Command),
    List(list::Command),
    Lint(lint::Command),
}
