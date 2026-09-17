//! Dispatches and implements `sq config inspect`.

use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::parser::ValueSource;

use crate::{
    Sq,
    cli::config::inspect,
    config::ConfigFile,
};

pub mod policy;

pub fn dispatch(sq: Sq, cmd: inspect::Command)
                -> Result<()>
{
    match cmd.subcommand {
        #[cfg(feature = "network")]
        inspect::Subcommands::Network(c) => network(sq, c),
        inspect::Subcommands::Paths(c) => paths(sq, c),
        inspect::Subcommands::Policy(c) => policy::dispatch(sq, c),
    }
}

/// Implements `sq config inspect network`.
#[cfg(feature = "network")]
fn network(sq: Sq, _: inspect::network::Command) -> Result<()> {
    fn may_use(what: &str, enabled: bool) -> String {
        format!("will {}use {}",
                if enabled { "" } else { "not " },
                what)
    }

    let o = &mut std::io::stdout();

    // First, sq network search, the most general interface.
    let use_wkd = sq.config.network_search_use_wkd(
        Some(true), Some(ValueSource::DefaultValue));
    wwriteln!(stream=o, initial_indent = " - ", "sq network search");
    wwriteln!(stream=o, initial_indent = "   - ", "{}",
              may_use("WKD", use_wkd));
    wwriteln!(stream=o, initial_indent = "     - ",
              "relevant setting: network.search.use-wkd");
    if use_wkd {
        wwriteln!(stream=o, initial_indent = "     - ", "see below for impact");
    }

    let use_dane = sq.config.network_search_use_dane(
        Some(true), Some(ValueSource::DefaultValue));
    wwriteln!(stream=o, initial_indent = "   - ", "{}",
              may_use("DANE", use_dane));
    wwriteln!(stream=o, initial_indent = "     - ",
              "relevant setting: network.search.use-dane");
    if use_dane {
        wwriteln!(stream=o, initial_indent = "     - ", "see below for impact");
    }

    let key_servers = sq.config.key_servers(
        &network::keyserver::DEFAULT_KEYSERVERS,
        Some(clap::parser::ValueSource::DefaultValue))
        .collect::<Vec<_>>();

    if key_servers.is_empty() {
        wwriteln!(stream=o, initial_indent = "   - ",
                  "will use no key servers by default");
    } else {
        wwriteln!(stream=o, initial_indent = "   - ",
                  "will use the following key servers");
        for s in &key_servers {
            wwriteln!(stream=o, initial_indent = "     - ", "{}", s);
        }
    }
    wwriteln!(stream=o, initial_indent = "       - ",
              "relevant setting: network.keyservers");
    if ! key_servers.is_empty() {
        wwriteln!(stream=o, initial_indent = "       - ", "see below for impact");
    }

    let iterations = sq.config.network_search_iterations(
        3, Some(ValueSource::DefaultValue));
    if iterations == 0 {
        wwriteln!(stream=o, initial_indent = "   - ",
                  "will not search iteratively from \
                   your original query to discover related \
                   certificates");
    } else {
        wwriteln!(stream=o, initial_indent = "   - ",
                  "will iteratively search up to {} steps from \
                   your original query to discover related \
                   certificates",
                  iterations.saturating_sub(1));
        wwriteln!(stream=o, initial_indent = "     - ",
                  "this will query certificates that you did not \
                   request, hopefully finding relevant related \
                   certificates, but increases the metadata \
                   leakage and may query \"suspicious\" \
                   certificates");
    }
    wwriteln!(stream=o, initial_indent = "     - ",
              "relevant setting: network.search.iterations");

    // Then, sq network keyserver search.
    wwriteln!(stream=o);
    wwriteln!(stream=o, initial_indent = " - ", "sq network keyserver search");
    if key_servers.is_empty() {
        wwriteln!(stream=o, initial_indent = "   - ",
                  "will use no key servers by default");
    } else {
        wwriteln!(stream=o, initial_indent = "   - ",
                  "will use the following key servers");
        for s in &key_servers {
            wwriteln!(stream=o, initial_indent = "     - ", "{}", s);
        }
    }
    wwriteln!(stream=o, initial_indent = "   - ",
              "relevant setting: network.keyservers");
    wwriteln!(stream=o, initial_indent = "   - ", "impact:");
    wwriteln!(stream=o, initial_indent = "     - ",
              "key servers and their operators can see all requests, \
               and learn about your contacts, and track you");
    wwriteln!(stream=o, initial_indent = "     - ",
              "although the traffic is encrypted, network observers \
               can use traffic analysis and observe the size of requests \
               and responses, and infer information about you and \
               your contacts, and track you");

    // Then, sq network wkd search.
    wwriteln!(stream=o);
    wwriteln!(stream=o, initial_indent = " - ", "sq network wkd search");
    wwriteln!(stream=o, initial_indent = "   - ", "impact:");
    wwriteln!(stream=o, initial_indent = "     - ",
              "WKD servers and their operators can see all requests, \
               and learn about your contacts, and track you");
    wwriteln!(stream=o, initial_indent = "     - ",
              "although the traffic is encrypted, network observers \
               can use traffic analysis, and observe the size of requests \
               and responses, and infer information about you and \
               your contacts, and possibly track you");

    // Then, sq network dane search.
    wwriteln!(stream=o);
    wwriteln!(stream=o, initial_indent = " - ", "sq network dane search");
    wwriteln!(stream=o, initial_indent = "   - ", "impact:");
    wwriteln!(stream=o, initial_indent = "     - ",
              "DNS servers and their operators can see all requests, \
               and learn about your contacts, and track you");
    wwriteln!(stream=o, initial_indent = "     - ",
              "the traffic is not encrypted, network observers \
               can see all requests, and learn about your contacts, \
               and track you");
    Ok(())
}

/// Implements `sq config inspect paths`.
fn paths(sq: Sq, _: inspect::paths::Command) -> Result<()> {
    let o = &mut std::io::stdout();

    // Whether we have emitted anything.
    let mut dirty = false;

    // Formats a path.
    let mut p = |path: &Path, name: &str, description: &str| -> Result<()> {
        if dirty {
            wwriteln!(o);
        }
        dirty = true;

        wwriteln!(stream=o, initial_indent = " - ", "{}", name);
        wwriteln!(stream=o, initial_indent = "   - ", "{}", path.display());

        if ! path.exists() {
            wwriteln!(stream=o, initial_indent = "   - ", "does not exist");
        }

        wwriteln!(stream=o, initial_indent = "   - ", "{}", description);

        Ok(())
    };

    if let Some(home) = &sq.home {
        p(home.location(), "home directory",
          "This holds the configuration file, and, unless overridden, \
           the certificate store and key store.",
        )?;

        p(&ConfigFile::file_name(&home), "config file",
          "sq's configuration file.",
        )?;
    }

    p(&PathBuf::from(ConfigFile::global_crypto_policy_file()),
      "global cryptographic policy",
      "This is the global cryptographic policy file.  If it exists, it \
       is read before reading in the policy in sq's configuration file, \
       which will refine the global one.",
    )?;

    if let Some(policy_path) = sq.config.policy_path() {
        p(policy_path,
          "referenced cryptographic policy",
          "This is the cryptographic policy file referenced in sq's \
           configuration file.  It is read after the global policy, \
           and before the policy embedded in sq's configuration file, \
           which will refine the global and referenced one.",
        )?;
    }

    if let Some(cert_store) = sq.cert_store_base() {
        p(&cert_store, "certificate store",
          "This holds all the certificates, indices for faster lookup, \
           and some additional certificates like the trust root.",
        )?;
    }

    if let Ok(Some(key_store)) = sq.key_store_path() {
        p(&key_store, "key store",
          "This holds all the keys, either directly for those in the \
           `softkeys` backend, or indirectly, using some configuration \
           and metadata.",
        )?;
    }

    Ok(())
}
