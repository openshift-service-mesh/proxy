use clap::ArgMatches;

use sequoia_openpgp as openpgp;
use openpgp::Result;

pub mod link;
pub mod path;
pub mod vouch;

use crate::cli;

use crate::Sq;
use crate::common::pki::authenticate;
use crate::commands::pki::authenticate::AuthenticateContext;
use crate::commands::pki::authenticate::Query;

pub fn dispatch(sq: Sq, cli: cli::pki::Command, matches: &ArgMatches)
                -> Result<()>
{
    tracer!(TRACE, "pki::dispatch");

    let matches = matches.subcommand().unwrap().1;
    use cli::pki::*;
    match cli.subcommand {
        // Authenticate a given binding.
        Subcommands::Authenticate(authenticate::Command {
            userid, gossip, unusable, certification_network,
            trust_amount, cert, show_paths,
        }) => {
            assert_eq!(cert.len(), 1);
            assert_eq!(userid.len(), 1);

            authenticate(
                &mut std::io::stdout(),
                &sq,
                AuthenticateContext::PKI,
                Query::for_binding(cert, userid),
                *gossip,
                *unusable,
                *certification_network,
                *trust_amount,
                *show_paths,
            )?
        }

        // Find all authenticated bindings for a given User ID, list
        // the certificates.
        Subcommands::Lookup(lookup::Command {
            gossip, unusable, certification_network, trust_amount,
            userid, show_paths,
        }) => {
            assert_eq!(userid.len(), 1);

            authenticate(
                &mut std::io::stdout(),
                &sq,
                AuthenticateContext::PKI,
                userid.into(),
                *gossip,
                *unusable,
                *certification_network,
                *trust_amount,
                *show_paths)?;
        }

        // Find and list all authenticated bindings for a given
        // certificate.
        Subcommands::Identify(identify::Command {
            gossip, unusable, certification_network, trust_amount,
            cert, show_paths,
        }) => {
            assert_eq!(cert.len(), 1);

            authenticate(
                &mut std::io::stdout(),
                &sq,
                AuthenticateContext::PKI,
                cert.into(),
                *gossip,
                *unusable,
                *certification_network,
                *trust_amount,
                *show_paths)?;
        }

        // Authenticates a given path.
        Subcommands::Path(command) =>
            self::path::path(sq, command)?,

        Subcommands::Vouch(command) =>
            self::vouch::vouch(sq, command, matches)?,

        Subcommands::Link(command) =>
            self::link::link(sq, command)?,
    }

    Ok(())
}
