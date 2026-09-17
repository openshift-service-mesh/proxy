//! Dispatches `sq key subkey`.

use clap::ArgMatches;

use crate::Result;
use crate::Sq;
use crate::cli::key::subkey::Command;

mod add;
mod bind;
mod delete;
mod expire;
mod export;
mod password;
mod revoke;

pub fn dispatch(sq: Sq, command: Command, matches: &ArgMatches) -> Result<()> {
    let matches = matches.subcommand().unwrap().1;
    match command {
        Command::Add(mut c) => {
            c.cipher_suite_source = matches.value_source("cipher_suite");
            add::dispatch(sq, c)?
        },
        Command::Export(c) => export::dispatch(sq, c)?,
        Command::Delete(c) => delete::dispatch(sq, c)?,
        Command::Password(c) => password::dispatch(sq, c)?,
        Command::Expire(c) => expire::dispatch(sq, c)?,
        Command::Revoke(c) => revoke::dispatch(sq, c)?,
        Command::Bind(c) => bind::bind(sq, c)?,
    }

    Ok(())
}
