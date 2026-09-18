use clap::Subcommand;

pub mod add;
pub mod bind;
pub mod delete;
pub mod expire;
pub mod export;
pub mod password;
pub mod revoke;

#[derive(Debug, Subcommand)]
#[clap(
    name = "subkey",
    about = "Manage subkeys",
    long_about = "\
Manage subkeys

Add new subkeys to an existing certificate, change their expiration, \
and revoke them.",
    subcommand_required = true,
    arg_required_else_help = true,
    disable_help_subcommand = true,
)]
#[non_exhaustive]
pub enum Command {
    Add(add::Command),
    Export(export::Command),
    Delete(delete::Command),
    Password(password::Command),
    Expire(expire::Command),
    Revoke(revoke::Command),
    Bind(bind::Command),
}
