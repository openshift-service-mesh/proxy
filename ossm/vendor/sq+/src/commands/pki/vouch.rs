use clap::ArgMatches;

use sequoia_openpgp as openpgp;
use openpgp::Result;

use crate::cli::pki::vouch;
use crate::Sq;

pub mod authorize;
pub mod add;
pub mod list;
pub mod replay;

pub fn vouch(sq: Sq, c: vouch::Command, matches: &ArgMatches) -> Result<()> {
    use vouch::Subcommands::*;
    let matches = matches.subcommand().unwrap().1;

    match c.subcommand {
        Add(mut c) => {
            c.expiration_source = matches.value_source("expiration");
            add::add(sq, c)
        },
        Authorize(mut c) => {
            c.expiration_source = matches.value_source("expiration");
            authorize::authorize(sq, c)
        },
        List(c) => {
            list::list(sq, c)
        },
        Replay(c) => {
            replay::replay(sq, c)
        },
    }
}
