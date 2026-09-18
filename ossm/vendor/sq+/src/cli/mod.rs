// XXX: The following comment should be an inner comment, but cannot
// until https://github.com/rust-lang/rust/issues/66920 is resolved.

/// Defines the command-line interface.
///
/// This module contains sq's command-line interface, i.e. the clap
/// definitions and associated types that can be used by clap.
///
/// We also generate manual pages from this module.  To that end,
/// `build.rs` includes this module, so all of its dependencies must
/// be also listed as build-dependencies.  Further, this module must
/// be self-contained, i.e. it must not use code from other parts of
/// sq.
///
/// # Interface guidelines
///
/// In order to provide a consistent user experience, please follow
/// these guidelines.
///
/// ## General guidelines
///
/// - The same subcommand or option in different places should do the
///   same or an equivalent thing, and should use the same phrases in
///   the help texts, to the extent possible.
///
/// - Subcommands SHOULD be of the form `sq [OBJECT..] VERB`.
///
///   - The object SHOULD be present, except for the top level
///     commands `encrypt`, `decrypt`, `sign`, `verify`, and
///     `inspect`.
///
/// - Subcommands SHOULD be grouped by topic, and ordered from most
///   often used to least often used.
///
/// - Use the imperative mood in the first sentence documenting
///   commands, subcommands, and arguments.
///
/// ## Terminology
///
/// - "certificate" or "cert" instead of "public key", "key", or
///   "TPK".
///
/// - "key" instead of "secret key", "private key", or "TSK".
///
/// - "key server" instead of "keyserver".
///
/// - "Web of Trust" instead of other variations.
///
/// ## Typography
///
/// - The first line of the about texts MUST NOT end in a period.
///
/// - To define terms, enclose them in double quotes: `"certificate"`.
///
/// - To include inline code fragments, like options or other
///   subcommands, use back ticks: `--foo` or `sq foo bar`.
///
/// - When referring to options, do not include the `VALUENAME`.
///
/// - Enclose URLs in angle brackets: `<https://example.org>`.
///
/// - Use a spaced en dash for parenthetical statements (` – `).
///
/// ## Examples
///
/// - Every subcommand SHOULD have at least one example.
///
/// - Every example MUST have a brief description.
///
/// - Examples SHOULD be short and to the point, they SHOULD NOT
///   include unnecessary options (like `--keyring`).
///
/// - Examples MUST use single quotes where necessary.
///
/// - Examples MUST NOT use unnecessary quoting.
// Workaround so that the above documentation is rendered somewhere in
// the API docs.
#[allow(dead_code)]
pub const USER_INTERFACE_GUIDELINES: () = ();

use std::borrow::Cow;
use std::fmt::Write;
use std::path::PathBuf;
use std::time::Duration;

/// Command-line parser for sq.
use clap::{Command, CommandFactory, Parser, Subcommand};
use clap::builder::StyledStr;

use sequoia_openpgp as openpgp;
use openpgp::Fingerprint;

#[macro_use]
pub mod examples;

pub mod cert;
pub mod config;
pub mod decrypt;
#[cfg(feature = "network")]
pub mod download;
pub mod encrypt;
pub mod inspect;
pub mod key;
pub mod keyring;
#[cfg(feature = "network")]
pub mod network;
pub mod output;
pub mod packet;
pub mod pki;
pub mod sign;
pub mod verify;
pub mod version;

pub mod types;
use types::paths::{StateDirectory, StateDirectoryValueParser};
use types::version::Version;
use types::version::VersionInvalidPositionValueParser;

/// Escapes `s` so when used on the command line, it is recognized as
/// a single token with the same value.
///
/// "{:?}" escapes a string, but it always adds quotes, which can be
/// ugly.  We first check check if adding quotes is necessary.
/// Specifically, if `s` just consists of alphanumeric characters and
/// a few others, then we don't need quotes.
pub fn escape_for_shell(s: &str) -> Cow<str> {
    if s.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || ['@', '.', ',', '+', '-', '_', '/'].contains(&c)
    })
    {
        Cow::Borrowed(s)
    } else {
        Cow::Owned(format!("{:?}", s))
    }
}

/// The seconds in a day
pub const SECONDS_IN_DAY : u64 = 24 * 60 * 60;
/// The seconds in a year
pub const SECONDS_IN_YEAR : u64 =
    // Average number of days in a year.
    (365.2422222 * SECONDS_IN_DAY as f64) as u64;
/// The default validity (in years) for keys and subkeys
pub const KEY_VALIDITY_IN_YEARS: u64 = 3;
/// The default validity period (as Duration) for keys and subkeys
pub const KEY_VALIDITY_DURATION: Duration =
    Duration::new(SECONDS_IN_YEAR * KEY_VALIDITY_IN_YEARS, 0);
/// The default validity (in years) for third party certifications
pub const THIRD_PARTY_CERTIFICATION_VALIDITY_IN_YEARS: u64 = 10;
/// The default validity period (as Duration) for third party certifications
pub const THIRD_PARTY_CERTIFICATION_VALIDITY_DURATION: Duration = Duration::new(
    SECONDS_IN_YEAR * THIRD_PARTY_CERTIFICATION_VALIDITY_IN_YEARS,
    0,
);

/// The default time (in days) to retire a certificate after rotation.
pub const KEY_ROTATE_RETIRE_IN_IN_DAYS: u64 = 182;
/// The default time to retire a certificate after rotation.
pub const KEY_ROTATE_RETIRE_IN_DURATION: Duration =
    Duration::new(SECONDS_IN_DAY * KEY_ROTATE_RETIRE_IN_IN_DAYS, 0);

pub const GLOBAL_OPTIONS_HEADER: &str = "Global Options";

/// Builds the top-level Clap command.
///
/// If `globals_hidden` is true, then top-level, global arguments are
/// marked as hidden, which means they won't be displayed in the help
/// output.
pub fn build(globals_hidden: bool) -> Command {
    let sq_version = Box::leak(
        format!(
            "{} (sequoia-openpgp {}, using {})",
            env!("CARGO_PKG_VERSION"),
            sequoia_openpgp::VERSION,
            sequoia_openpgp::crypto::backend()
        )
        .into_boxed_str(),
    ) as &str;

    let mut command = SqCommand::command()
        .version(sq_version)
    // To improve readability limit the width of the text columns.
        .max_term_width(100);

    // Change the globals to be hidden.
    if globals_hidden {
        fn add_after_help(command: &mut Command) {
            // We want to append to after_long_help.
            let mut after_long_help
                = if let Some(s) = command.get_after_long_help() {
                    let mut s = s.clone();
                    s.write_char('\n').expect("Can write to string");
                    s.write_char('\n').expect("Can write to string");
                    s
                } else if let Some(s) = command.get_after_help() {
                    // If after_long_help is not explicitly set, it
                    // falls back to after_help.  If we set
                    // after_long_help, the fallback no longer happens
                    // so we need to do it manually.
                    let mut s = s.clone();
                    s.write_char('\n').expect("Can write to string");
                    s.write_char('\n').expect("Can write to string");
                    s
                } else {
                    StyledStr::new()
                };

            after_long_help.write_str(&format!("\
{}:\n  See 'sq --help' for a description of the global options.",
                                               GLOBAL_OPTIONS_HEADER))
                .expect("Can write to string");

            *command = command.clone()
                .after_long_help(after_long_help);

            for sc in command.get_subcommands_mut() {
                add_after_help(sc);
            }
        }

        command = command
            .mut_args(|mut a| {
                if a.is_global_set() {
                    a = a.hide(globals_hidden);
                }
                a
            });

        add_after_help(&mut command);
    };

    command
}

/// Defines the CLI.
#[derive(Parser, Debug)]
#[clap(
    name = "sq",
    about = "A command-line frontend for Sequoia, an implementation of OpenPGP",
    long_about = "A command-line frontend for Sequoia, an implementation of OpenPGP

Functionality is grouped and available using subcommands.  This \
interface is not completely stateless.  In particular, the user's \
default certificate store is used.  This can be disabled using \
`--cert-store=none`.  Similarly, a key store is used to manage and \
protect secret key material.  This can be disabled using \
`--key-store=none`.

OpenPGP data can be provided in binary or ASCII armored form.  This \
will be handled automatically.  Emitted OpenPGP data is ASCII armored \
by default.

We use the term \"certificate\", or \"cert\" for short, to refer to OpenPGP \
keys that do not contain secrets.  Conversely, we use the term \"key\" \
to refer to OpenPGP keys that do contain secrets.
",
    subcommand_required = true,
    arg_required_else_help = true,
    disable_colored_help = true,
    disable_version_flag = true,
    // We want a top-level `help` subcommand, but we don't want
    // subcommands groups (like `sq pki`) to have a `help` subcommand.
    // Users get used to being able to use `help` instead of `--help`,
    // and then are confused when `sq pki authenticate help` (i.e.,
    // using the `help` subcommand on an action) doesn't work.
    //
    // Note: this option is recursive.  So if we disable it here, then
    // we have to enable it for all of the top-level subcommands.
    disable_help_subcommand = false,
)]
pub struct SqCommand {
    #[clap(
        long = "cli-version",
        global = true,
        value_parser = VersionInvalidPositionValueParser::default(),
        help_heading = GLOBAL_OPTIONS_HEADER,
        help = "Select a CLI version",
        long_help = format!("\
Select a CLI version

`sq`'s CLI is versioned using a semantic versioning scheme.  Setting \
this options causes `sq` to error out if it does not implement an \
interface that is compatible with the specified version.  For \
instance, if you set this to 1.1.0 and `sq` only implements version
1.0.0 of the interface, then `sq` will error out.

`sq` may implement multiple interfaces (e.g., 1.1.4, and 2.0.5).  By \
default, it selects the newest version.  As such, if you require a \
particular interface, you need to set this option for every call to \
`sq`.

This option must be the first option on the command line.

This version of `sq` implements version {}.{}.{} of the CLI interface.

Stable since 1.2.0.
",
                            env!("CARGO_PKG_VERSION_MAJOR"),
                            env!("CARGO_PKG_VERSION_MINOR"),
                            env!("CARGO_PKG_VERSION_PATCH")),
    )]
    pub cli_version: Option<Version>,

    #[clap(
        long = "overwrite",
        global = true,
        help_heading = GLOBAL_OPTIONS_HEADER,
        help = "Overwrite existing files",
    )]
    pub overwrite: bool,

    #[clap(
        long = "home",
        value_name = "PATH",
        env = "SEQUOIA_HOME",
        global = true,
        help_heading = GLOBAL_OPTIONS_HEADER,
        help = "Set the home directory",
        long_help = format!("\
Set the home directory

Sequoia's default home directory is `{}`.  When using the default \
location, files are placed according to the local standard, \
e.g., the XDG Base Directory Specification.  When an alternate \
location is specified, the user data, configuration files, and \
cache data are placed under a single, unified directory.  This is \
a lightweight way to partially isolate `sq`.

Use 'default' to explicitly use the default location, use 'none' to \
not use a home directory.",
            sequoia_directories::Home::default_location()
                .map(|p| {
                    let p = p.display().to_string();
                    if let Some(home) = dirs::home_dir() {
                        let home = home.display().to_string();
                        if let Some(rest) = p.strip_prefix(&home) {
                            return format!("$HOME{}", rest);
                        }
                    }
                    p
                })
                .unwrap_or("<unknown>".to_string())),
        value_parser = StateDirectoryValueParser::default(),
    )]
    pub home: Option<StateDirectory>,

    #[clap(
        long = "key-store",
        value_name = "PATH",
        env = "SEQUOIA_KEY_STORE",
        global = true,
        help_heading = GLOBAL_OPTIONS_HEADER,
        help = "Override the key store server and its data",
        long_help = format!("Override the key store server and its data

A key store server manages and protects secret key material.  By \
default, `sq` connects to the key store server for Sequoia's default \
home directory (see `--home`), {}.  If no key store server is running, \
one is started.

This option causes `sq` to use an alternate key store server.  If \
necessary, a key store server is started, and configured to look for \
its data in the specified location.

Use 'default' to explicitly use the default server, use 'none' to \
not use a key store.",
            sequoia_directories::Home::default()
                .map(|home| {
                    let p = home.data_dir(sequoia_directories::Component::Keystore);
                    let p = p.display().to_string();
                    if let Some(home) = dirs::home_dir() {
                        let home = home.display().to_string();
                        if let Some(rest) = p.strip_prefix(&home) {
                            return format!("$HOME{}", rest);
                        }
                    }
                    p
                })
                .unwrap_or("<unknown>".to_string())),
        value_parser = StateDirectoryValueParser::default(),
    )]
    pub key_store: Option<StateDirectory>,

    #[clap(
        long = "cert-store",
        value_name = "PATH",
        env = "SEQUOIA_CERT_STORE",
        global = true,
        help_heading = GLOBAL_OPTIONS_HEADER,
        help = "Specify the location of the certificate store",
        long_help = format!("\
Specify the location of the certificate store

By default, `sq` uses \
the OpenPGP certificate directory in Sequoia's home directory (see `--home`), \
{}.  This can be overridden by setting the `PGP_CERT_D` environment \
variable.

Use 'default' to explicitly use the default cert store, use 'none' to \
not use a cert store.",
            sequoia_directories::Home::default()
                .map(|home| {
                    let p = home.data_dir(sequoia_directories::Component::CertD);
                    let p = p.display().to_string();
                    if let Some(home) = dirs::home_dir() {
                        let home = home.display().to_string();
                        if let Some(rest) = p.strip_prefix(&home) {
                            return format!("$HOME{}", rest);
                        }
                    }
                    p
                })
                .unwrap_or("<unknown>".to_string())),
        value_parser = StateDirectoryValueParser::default(),
    )]
    pub cert_store: Option<StateDirectory>,

    #[clap(
        long,
        value_name = "PATH",
        global = true,
        help_heading = GLOBAL_OPTIONS_HEADER,
        help = "Specify the location of a keyring to use",
        long_help = "\
Specify the location of a keyring to use

Keyrings are used in \
addition to any certificate store.  The content of the keyring is \
not imported into the certificate store.  When a certificate is \
looked up, it is looked up in all keyrings and any certificate \
store, and the results are merged together."
    )]
    pub keyring: Vec<PathBuf>,

    #[clap(
        long = "known-notation",
        value_name = "NOTATION",
        global = true,
        help_heading = GLOBAL_OPTIONS_HEADER,
        help = "Add NOTATION to the list of known notations",
        long_help = "Add NOTATION to the list of known notations

This is used when validating signatures. \
Signatures that have unknown notations with the \
critical bit set are considered invalid."
    )]
    // TODO is this the right type?
    pub known_notation: Vec<String>,

    #[clap(
        long = "time",
        allow_hyphen_values = true,
        value_name = "TIME",
        help = "Set the reference time as an ISO 8601 formatted timestamp",
        global = true,
        help_heading = GLOBAL_OPTIONS_HEADER,
        long_help = "\
Set the reference time as an ISO 8601 formatted timestamp

Normally, \
commands use the current time as the reference time.  This argument allows \
the user to use a difference reference time.  For instance, when creating a \
key using `sq key generate`, the creation time is normally set to the \
current time, but can be overridden using this option.  Similarly, when \
verifying a message, the message is verified with respect to the current \
time.  This option allows the user to use a different time.

TIME is interpreted as an ISO 8601 timestamp.  To set the \
certification time to July 21, 2013 at midnight UTC, you can do:

$ sq --time 20130721 verify --message msg.pgp

To include a time, say 5:50 AM, add a T, the time and optionally the timezone \
(the default timezone is UTC):

$ sq --time 20130721T0550+0200 --message verify msg.pgp
",
    )]
    pub time: Option<types::Time>,
    #[clap(
        long = "policy-as-of",
        allow_hyphen_values = true,
        value_name = "TIME",
        help = "Select the cryptographic policy as of the specified time",
        global = true,
        help_heading = GLOBAL_OPTIONS_HEADER,
        long_help = "\
Select the cryptographic policy as of the specified time

The time is \
expressed as an ISO 8601 formatted timestamp.  The policy determines \
what cryptographic constructs are allowed.

If you are working with a message that sq rejects, because it is \
protected by cryptographic constructs that are now considered broken, \
you can use this option to select a different cryptographic policy.  \
If you are relying on the cryptography, e.g., you are verifying a \
signature, then you should only do this if you are confident that the \
message hasn't been tampered with.

TIME is interpreted as an ISO 8601 timestamp.  To set the \
policy time to January 1, 2007 at midnight UTC, you can do:

$ sq --policy-as-of 20070101 verify --message msg.pgp

Defaults to the reference time, which can be set using --time.
",
    )]
    pub policy_as_of: Option<types::Time>,

    #[clap(
        long = "trust-root",
        value_name = "FINGERPRINT|KEYID",
        global = true,
        help_heading = GLOBAL_OPTIONS_HEADER,
        help = "Consider the specified certificate to be a trust root",
        long_help = "Consider the specified certificate to be a trust root

Trust roots are used by trust models, e.g., the Web of \
Trust, to authenticate certificates and User IDs."
    )]
    pub trust_roots: Vec<Fingerprint>,
    #[clap(
        long,
        value_name = "FILE",
        global = true,
        help_heading = GLOBAL_OPTIONS_HEADER,
        help = "Seed the password cache with the specified password",
        long_help = "\
Seed the password cache with the specified password

The password is added to the password cache.  When decrypting secret \
key material, the password cache is only used if the key is not \
protected by a retry counter, which automatically locks the key if \
a wrong password is entered too many times.

Note that the entire key file will be used as the password, including \
any surrounding whitespace like a trailing newline.",
    )]
    pub password_file: Vec<PathBuf>,

    #[clap(
        short = 'v',
        long,
        global = true,
        help_heading = GLOBAL_OPTIONS_HEADER,
        help = "Be more verbose",
        long_help = config::augment_help(
            "ui.verbose",
            "Be more verbose"),
    )]
    pub verbose: bool,

    #[clap(
        short = 'q',
        long = "quiet",
        global = true,
        help_heading = GLOBAL_OPTIONS_HEADER,
        help = "Be more quiet",
        long_help = config::augment_help(
            "ui.quiet",
            "Be more quiet"),
        conflicts_with = "verbose",
    )]
    pub quiet: bool,

    #[clap(
        long = "batch",
        global = true,
        help_heading = GLOBAL_OPTIONS_HEADER,
        help = "Prevents any kind of prompting",
        long_help = "\
Prevents any kind of prompting

Enables batch mode.  In batch mode, sq will never ask for user input,
such as prompting for passwords.
",
    )]
    pub batch: bool,

    #[clap(subcommand)]
    pub subcommand: SqSubcommands,
}

/// The order of top-level subcommands is:
///
///   - Encryption & decryption
///   - Signing & verification
///   - Inspection
///   - Key & cert-ring management
///   - Key discovery & networking
///   - Tools for developers, maintainers, forensic specialists
///
/// The order is derived from the order of variants in this enum.
#[derive(Debug, Subcommand)]
pub enum SqSubcommands {
    Encrypt(encrypt::Command),
    Decrypt(decrypt::Command),

    Sign(sign::Command),
    Verify(verify::Command),
    #[cfg(feature = "network")]
    Download(download::Command),

    Inspect(inspect::Command),

    Cert(cert::Command),
    Key(key::Command),
    Pki(pki::Command),

    #[cfg(feature = "network")]
    Network(network::Command),

    Keyring(keyring::Command),
    Packet(packet::Command),

    Config(config::Command),
    Version(version::Command),
}
