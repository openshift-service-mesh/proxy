use clap::ArgMatches;

use sequoia_openpgp as openpgp;
use openpgp::Result;

use crate::cli;
use crate::Sq;

mod approvals;
mod delete;
mod expire;
mod export;
mod import;
use import::import;
mod list;
use list::list;
mod generate;
use generate::generate;
mod password;
mod rotate;
mod revoke;
use revoke::certificate_revoke;
mod subkey;
pub mod userid;

pub fn dispatch(sq: Sq, command: cli::key::Command, matches: &ArgMatches)
                -> Result<()>
{
    let matches = matches.subcommand().unwrap().1;
    use cli::key::Subcommands::*;
    match command.subcommand {
        List(c) => list(sq, c)?,
        Generate(mut c) => {
            c.cipher_suite_source = matches.value_source("cipher_suite");
            c.profile_source = matches.value_source("profile");
            generate(sq, c)?
        },
        Rotate(mut c) => {
            c.cipher_suite_source = matches.value_source("cipher_suite");
            c.profile_source = matches.value_source("profile");
            rotate::dispatch(sq, c)?
        }
        Import(c) => import(sq, c)?,
        Export(c) => export::dispatch(sq, c)?,
        Delete(c) => delete::dispatch(sq, c)?,
        Password(c) => password::dispatch(sq, c)?,
        Expire(c) => expire::dispatch(sq, c)?,
        Userid(c) => userid::dispatch(sq, c)?,
        Revoke(c) => certificate_revoke(sq, c)?,
        Subkey(c) => subkey::dispatch(sq, c, matches)?,
        Approvals(c) => approvals::dispatch(sq, c)?,
    }
    Ok(())
}
