//! Command-line parser for `sq pki`.

use std::ops::Deref;

use clap::Parser;

use crate::cli::types::TrustAmount;

pub mod authenticate;
pub mod identify;
pub mod lookup;
pub mod link;
pub mod path;
pub mod vouch;

#[derive(Debug, Parser)]
#[clap(
    name = "pki",
    about = "Authenticate certs using the Web of Trust",
    long_about =
"Authenticate certs using the Web of Trust

The \"Web of Trust\" is a decentralized trust model popularized by PGP. \
It is a superset of X.509, which is a hierarchical trust model, and is \
the most popular trust model on the public internet today.  As used on \
the public internet, however, X.509 relies on a handful of global \
certification authorities (CAs) who often undermine its security.

The Web of Trust is more nuanced than X.509.  Using the Web of Trust, \
require multiple, independent paths to authenticate a binding by only \
partially trusting CAs.  This prevents a single bad actor from \
compromising their security.  And those who have stronger security \
requirements can use the Web of Trust in a completely decentralized \
manner where only the individuals they select – who are not \
necessarily institutions – act as trusted introducers.
",
    subcommand_required = true,
    arg_required_else_help = true,
    disable_help_subcommand = true,
)]
pub struct Command {
    #[command(subcommand)]
    pub subcommand: Subcommands,
}

#[derive(clap::Subcommand, Debug)]
pub enum Subcommands {
    Authenticate(authenticate::Command),
    Lookup(lookup::Command),
    Identify(identify::Command),
    Vouch(vouch::Command),
    Link(link::Command),
    Path(path::Command),
}

#[derive(clap::Args, Debug)]
pub struct GossipArg {
    /// Treats all certificates as unreliable trust roots
    ///
    /// This option is useful for figuring out what others think about
    /// a certificate (i.e., gossip or hearsay).  In other words, this
    /// finds arbitrary paths to a particular certificate.
    ///
    /// Gossip is useful in helping to identify alternative ways to
    /// authenticate a certificate.  For instance, imagine Ed wants to
    /// authenticate Laura's certificate, but asking her directly is
    /// inconvenient.  Ed discovers that Micah has certified Laura's
    /// certificate, but Ed hasn't yet authenticated Micah's
    /// certificate.  If Ed is willing to rely on Micah as a trusted
    /// introducer, and authenticating Micah's certificate is easier
    /// than authenticating Laura's certificate, then Ed has learned
    /// about an easier way to authenticate Laura's certificate.
    ///
    /// Stable since 1.1.0.
    #[arg(long)]
    pub gossip: bool,
}

impl Deref for GossipArg {
    type Target = bool;

    fn deref(&self) -> &Self::Target {
        &self.gossip
    }
}

#[derive(clap::Args, Debug)]
pub struct UnusableArg {
    /// Show bindings that are unusable
    ///
    /// Normally, unusable certificates and bindings are not shown.
    /// This option considers bindings, even if they are not unusable,
    /// because they (or the certificates) are not valid according to
    /// the policy, are revoked, or are not live.
    ///
    /// This option only makes sense with `--gossip`, because unusable
    /// bindings are still considered unauthenticated.
    ///
    /// Stable since 1.1.0.
    #[arg(long, requires="gossip")]
    pub unusable: bool,
}

impl Deref for UnusableArg {
    type Target = bool;

    fn deref(&self) -> &Self::Target {
        &self.unusable
    }
}

#[derive(clap::Args, Debug)]
pub struct CertificationNetworkArg {
    /// Treats the network as a certification network
    ///
    /// Normally, the authentication machinery treats the Web of Trust
    /// network as an authentication network where a certification
    /// only means that the binding is correct, not that the target
    /// should be treated as a trusted introducer.  In a certification
    /// network, the targets of certifications are treated as trusted
    /// introducers with infinite depth, and any regular expressions
    /// are ignored.  Note: The trust amount remains unchanged.  This
    /// is how most so-called PGP path-finding algorithms work.
    #[arg(long)]
    pub certification_network: bool,
}

impl Deref for CertificationNetworkArg {
    type Target = bool;

    fn deref(&self) -> &Self::Target {
        &self.certification_network
    }
}

#[derive(clap::Args, Debug)]
pub struct RequiredTrustAmountArg {
    /// The required amount of trust
    ///
    /// 120 indicates full authentication; values less than 120
    /// indicate partial authentication.  When
    /// `--certification-network` is passed, this defaults to 1200,
    /// i.e., this command tries to find 10 paths.
    #[arg(long="amount", value_name = "AMOUNT")]
    pub trust_amount: Option<TrustAmount<usize>>,
}

impl Deref for RequiredTrustAmountArg {
    type Target = Option<TrustAmount<usize>>;

    fn deref(&self) -> &Self::Target {
        &self.trust_amount
    }
}

#[derive(clap::Args, Debug)]
pub struct ShowPathsArg {
    /// Show why a binding is authenticated
    ///
    /// By default, only a user ID and certificate binding's degree of
    /// authentication (a value between 0 and 120) is shown.  This
    /// changes the output to also show how that value was computed by
    /// showing the paths from the trust roots to the bindings.
    #[arg(long)]
    pub show_paths: bool,
}

impl Deref for ShowPathsArg {
    type Target = bool;

    fn deref(&self) -> &Self::Target {
        &self.show_paths
    }
}
