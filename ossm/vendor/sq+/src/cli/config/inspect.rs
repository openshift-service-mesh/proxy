//! Command-line parser for `sq config inspect`.

use clap::{
    Parser,
    Subcommand,
};

#[cfg(feature = "network")]
pub mod network;
pub mod paths;
pub mod policy;

#[derive(Debug, Parser)]
#[clap(
    name = "inspect",
    about = "Inspect effective configuration details",
    long_about = "\
Inspect effective configuration details

This subcommand can be used to inspect various aspects of the \
effective configuration, such as various relevant paths, \
the cryptographic policy, the network configuration, etc.
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
#[non_exhaustive]
pub enum Subcommands {
    Paths(paths::Command),
    #[cfg(feature = "network")]
    Network(network::Command),
    Policy(policy::Command),
}
