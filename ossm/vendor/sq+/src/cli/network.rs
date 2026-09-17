//! Command-line parser for `sq network`.

use clap::{Parser, Subcommand};

pub mod dane;
pub mod keyserver;
pub mod search;
pub mod wkd;

#[derive(Parser, Debug)]
#[clap(
    name = "network",
    about = "Retrieve and publish certificates over the network",
    long_about =
"Retrieve and publish certificates over the network

OpenPGP certificates can be discovered and updated from, and published \
on services accessible over the network.  This is a collection of \
commands to interact with these services.
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
    Search(search::Command),
    Keyserver(keyserver::Command),
    Wkd(wkd::Command),
    Dane(dane::Command),
}
