//! Configuration model and file parsing.

use std::{
    collections::{BTreeSet, HashSet},
    fs,
    io,
    path::{Path, PathBuf},
    time::SystemTime,
};

use aho_corasick::AhoCorasick;
use anyhow::Context;
use clap::{ValueEnum, parser::ValueSource};

use toml_edit::{
    DocumentMut,
    Item,
    Table,
    Value,
};

use sequoia_openpgp::{
    Fingerprint,
    policy::StandardPolicy,
};
use url::Url;
use sequoia_directories::{Component, Home};
use sequoia_policy_config::ConfiguredStandardPolicy;

use crate::{
    Result,
    cli,
    cli::config::Augmentations,
};

/// Represents configuration at runtime.
///
/// This struct is manipulated when parsing the configuration file.
/// It is available as `Sq::config`, with suitable accessors that
/// handle the precedence of the various sources.
pub struct Config {
    /// Whether to be more verbose.
    verbose: bool,

    /// Whether to be more quiet.
    quiet: bool,

    /// Whether to show hints.
    hints: Option<bool>,

    /// The set of encryption certs selected using `--for-self`.
    encrypt_for_self: BTreeSet<Fingerprint>,

    /// The default profile for encryption containers.
    encrypt_profile: Option<cli::types::Profile>,

    /// The set of signing keys selected using `--signer-self`.
    sign_signer_self: BTreeSet<Fingerprint>,

    /// The default certification key selected using
    /// `--certifier-self`.
    pki_vouch_certifier_self: Option<Fingerprint>,

    /// The default validity period for third-party certifications.
    pki_vouch_expiration: Option<cli::types::Expiration>,

    policy_path: Option<PathBuf>,
    policy_inline: Option<Vec<u8>>,

    /// The default cipher suite for newly generated keys.
    cipher_suite: Option<sequoia_openpgp::cert::CipherSuite>,

    /// The default profile for newly generated keys.
    key_generate_profile: Option<cli::types::Profile>,

    /// The set of keyservers to use.
    key_servers: Option<Vec<Url>>,

    /// Iterations for network search.
    network_search_iterations: Option<u8>,

    /// Whether network search should use WKD.
    network_search_use_wkd: Option<bool>,

    /// Whether network search should use DANE.
    network_search_use_dane: Option<bool>,

    /// The location of the backend server executables.
    servers_path: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            verbose: false,
            quiet: false,
            hints: None,
            encrypt_for_self: Default::default(),
            encrypt_profile: None,
            sign_signer_self: Default::default(),
            pki_vouch_certifier_self: None,
            pki_vouch_expiration: None,
            policy_path: None,
            policy_inline: None,
            cipher_suite: None,
            key_generate_profile: None,
            key_servers: None,
            network_search_iterations: None,
            network_search_use_wkd: None,
            network_search_use_dane: None,
            servers_path: None,
        }
    }
}

impl Config {
    /// Sets the verbose setting.
    ///
    /// Handles the precedence of the various sources, but since this
    /// is a global flag and accessed very often, this is a setter and
    /// we do this once, when initializing the configuration object:
    ///
    /// - If the flag is given, use the given value.
    /// - If the command line flag is not given, then
    ///   - use the value from the configuration file (if any),
    ///   - or use the default value.
    pub fn init_verbose(&mut self, cli: bool, source: Option<ValueSource>)
    {
        match source.expect("set by the cli parser") {
            ValueSource::DefaultValue => {
                // Use the value from the configuration file.
            },
            _ => self.verbose = cli,
        }
    }

    /// Returns the verbose setting.
    ///
    /// The precedence of the various sources has been handled at
    /// initialization time.
    pub fn verbose(&self) -> bool {
        self.verbose
    }

    /// Sets the quiet setting.
    ///
    /// Handles the precedence of the various sources, but since this
    /// is a global flag and accessed very often, this is a setter and
    /// we do this once, when initializing the configuration object:
    ///
    /// - If the flag is given, use the given value.
    /// - If the command line flag is not given, then
    ///   - use the value from the configuration file (if any),
    ///   - or use the default value.
    pub fn init_quiet(&mut self, cli: bool, source: Option<ValueSource>)
    {
        match source.expect("set by the cli parser") {
            ValueSource::DefaultValue => {
                // Use the value from the configuration file.
            },
            _ => self.quiet = cli,
        }
    }

    /// Returns the quiet setting.
    ///
    /// The precedence of the various sources has been handled at
    /// initialization time.
    pub fn quiet(&self) -> bool {
        self.quiet
    }

    /// Returns whether to show hints.
    pub fn hints(&self) -> bool {
        self.hints.unwrap_or(! self.quiet())
    }

    /// Returns the certificates that should be added to the list of
    /// recipients if `encrypt --for-self` is given.
    pub fn encrypt_for_self(&self) -> &BTreeSet<Fingerprint> {
        &self.encrypt_for_self
    }

    /// Returns the default profile for encryption containers.
    ///
    /// Handles the precedence of the various sources:
    ///
    /// - If the flag is given, use the given value.
    /// - If the command line flag is not given, then
    ///   - use the value from the configuration file (if any),
    ///   - or use the default value.
    pub fn encrypt_profile(&self, cli: &cli::types::Profile,
                                source: Option<ValueSource>)
                                -> cli::types::Profile
    {
        match source.expect("set by the cli parser") {
            ValueSource::DefaultValue =>
                self.encrypt_profile.as_ref().unwrap_or(cli),
            _ => cli,
        }.clone()
    }

    /// Returns the keys that should be added to the list of
    /// signers if `--signer-self` is given.
    pub fn sign_signer_self(&self) -> &BTreeSet<Fingerprint> {
        &self.sign_signer_self
    }

    /// Returns the key that should be used as certifier if
    /// `--certifier-self` is given.
    pub fn pki_vouch_certifier_self(&self) -> &Option<Fingerprint> {
        &self.pki_vouch_certifier_self
    }

    /// Returns the expiration for third-party certifications.
    ///
    /// Handles the precedence of the various sources:
    ///
    /// - If the flag is given, use the given value.
    /// - If the command line flag is not given, then
    ///   - use the value from the configuration file (if any),
    ///   - or use the default value.
    pub fn pki_vouch_expiration(&self, cli: &cli::types::Expiration,
                                source: Option<ValueSource>)
                                -> cli::types::Expiration
    {
        match source.expect("set by the cli parser") {
            ValueSource::DefaultValue =>
                self.pki_vouch_expiration.as_ref().unwrap_or(cli),
            _ => cli,
        }.clone()
    }

    /// Returns the path to the referenced cryptographic policy, if
    /// any.
    pub fn policy_path(&self) -> Option<&Path> {
        self.policy_path.as_deref()
    }

    /// Returns the cryptographic policy.
    ///
    /// We read in the default policy configuration, the configuration
    /// referenced in the configuration file, and the inline policy.
    pub fn policy(&self, at: SystemTime)
                  -> Result<StandardPolicy<'static>>
    {
        let mut policy = ConfiguredStandardPolicy::at(at);

        policy.parse_default_config()?;

        if let Some(p) = &self.policy_path {
            if ! policy.parse_config_file(p)? {
                return Err(anyhow::anyhow!(
                    "referenced policy file {:?} does not exist", p));
            }
        }

        if let Some(p) = &self.policy_inline {
            policy.parse_bytes(p)?;
        }

        Ok(policy.build())
    }

    /// Returns the cipher suite for generating new keys.
    ///
    /// Handles the precedence of the various sources:
    ///
    /// - If the flag is given, use the given value.
    /// - If the command line flag is not given, then
    ///   - use the value from the configuration file (if any),
    ///   - or use the default value.
    pub fn cipher_suite(&self, cli: &cli::key::CipherSuite,
                        source: Option<ValueSource>)
                        -> sequoia_openpgp::cert::CipherSuite
    {
        match source.expect("set by the cli parser") {
            ValueSource::DefaultValue =>
                self.cipher_suite.unwrap_or_else(
                    || cli.as_ciphersuite()),
            _ => cli.as_ciphersuite(),
        }
    }

    /// Returns the profile for generating new keys.
    ///
    /// Handles the precedence of the various sources:
    ///
    /// - If the flag is given, use the given value.
    /// - If the command line flag is not given, then
    ///   - use the value from the configuration file (if any),
    ///   - or use the default value.
    pub fn key_generate_profile(&self, cli: &cli::types::Profile,
                                source: Option<ValueSource>)
                                -> cli::types::Profile
    {
        match source.expect("set by the cli parser") {
            ValueSource::DefaultValue =>
                self.key_generate_profile.as_ref().unwrap_or(cli),
            _ => cli,
        }.clone()
    }

    /// Returns the key servers to query or publish.
    ///
    /// Handles the precedence of the various sources:
    ///
    /// - If the flag is given, use the given value.
    /// - If the command line flag is not given, then
    ///   - use the value from the configuration file (if any),
    ///   - or use the default value.
    pub fn key_servers<'s, S>(&'s self, cli: &'s [S],
                              source: Option<ValueSource>)
                              -> impl Iterator<Item = &'s str> + 's
    where
        S: AsRef<str> + 's,
    {
        match source.expect("set by the cli parser") {
            ValueSource::DefaultValue =>
                self.key_servers.as_ref()
                .map(|s| Box::new(s.iter().map(|s| s.as_str()))
                     as Box<dyn Iterator<Item = &str>>)
                .unwrap_or_else(|| Box::new(cli.iter().map(|s| s.as_ref()))
                                as Box<dyn Iterator<Item = &str>>),
            _ => Box::new(cli.iter().map(|s| s.as_ref()))
                as Box<dyn Iterator<Item = &str>>,
        }
    }

    /// Returns the iteration count for network search.
    ///
    /// Handles the precedence of the various sources:
    ///
    /// - If the flag is given, use the given value.
    /// - If the command line flag is not given, then
    ///   - use the value from the configuration file (if any),
    ///   - or use the default value.
    pub fn network_search_iterations(&self, cli: u8,
                                     source: Option<ValueSource>)
                                     -> u8
    {
        match source.expect("set by the cli parser") {
            ValueSource::DefaultValue =>
                self.network_search_iterations.unwrap_or(cli),
            _ => cli,
        }
    }

    /// Returns whether network search should use WKD.
    ///
    /// Handles the precedence of the various sources:
    ///
    /// - If the flag is given, use the given value.
    /// - If the command line flag is not given, then
    ///   - use the value from the configuration file (if any),
    ///   - or use the default value.
    pub fn network_search_use_wkd(&self, cli: Option<bool>,
                                  source: Option<ValueSource>)
                                  -> bool
    {
        let cli = cli.expect("has a default");
        match source.expect("set by the cli parser") {
            ValueSource::DefaultValue =>
                self.network_search_use_wkd.unwrap_or(cli),
            _ => cli,
        }
    }

    /// Returns whether network search should use DANE.
    ///
    /// Handles the precedence of the various sources:
    ///
    /// - If the flag is given, use the given value.
    /// - If the command line flag is not given, then
    ///   - use the value from the configuration file (if any),
    ///   - or use the default value.
    pub fn network_search_use_dane(&self, cli: Option<bool>,
                                  source: Option<ValueSource>)
                                  -> bool
    {
        let cli = cli.expect("has a default");
        match source.expect("set by the cli parser") {
            ValueSource::DefaultValue =>
                self.network_search_use_dane.unwrap_or(cli),
            _ => cli,
        }
    }

    /// Returns the path to the backend servers.
    pub fn servers_path(&self) -> Option<&Path> {
        self.servers_path.as_ref().map(|p| p.as_path())
    }
}

/// Holds the document tree of the configuration file.
#[derive(Debug, Default)]
pub struct ConfigFile {
    doc: DocumentMut,
}

impl ConfigFile {
    /// A template for the configuration containing the default
    /// values.
    const TEMPLATE: &'static str = "\
# Configuration template for sq <SQ-VERSION>
<SQ-CONFIG-PATH-HINT>

[ui]
#verbosity = \"default\" # or \"verbose\" or \"quiet\"
#hints = true

[encrypt]
#for-self = [\"fingerprint of your key\"]
#profile = <DEFAULT-ENCRYPT-PROFILE>

[sign]
#signer-self = [\"fingerprint of your key\"]

[pki.vouch]
#certifier-self = \"fingerprint of your key\"
#expiration = \"<DEFAULT-PKI-VOUCH-EXPIRATION>y\"

[key.generate]
#cipher-suite = <DEFAULT-CIPHER-SUITE>
#profile = <DEFAULT-KEY-GENERATE-PROFILE>

[network]
#keyservers = <DEFAULT-KEY-SERVERS>

[network.search]
#iterations = 3
#use-wkd = true
#use-dane = true

[servers]
#path = <DEFAULT-SERVERS-PATH>

[policy]
#path = <DEFAULT-POLICY-FILE>

# The policy can be inlined, either alternatively, or additionally,
# like so:

<DEFAULT-POLICY-INLINE>
";

    /// Patterns to match on in `Self::DEFAULT` to be replaced with
    /// the default values.
    const TEMPLATE_PATTERNS: &'static [&'static str] = &[
        "<SQ-VERSION>",
        "<SQ-CONFIG-PATH-HINT>",
        "<DEFAULT-ENCRYPT-PROFILE>",
        "<DEFAULT-PKI-VOUCH-EXPIRATION>",
        "<DEFAULT-CIPHER-SUITE>",
        "<DEFAULT-KEY-GENERATE-PROFILE>",
        "<DEFAULT-KEY-SERVERS>",
        "<DEFAULT-SERVERS-PATH>",
        "<DEFAULT-POLICY-FILE>",
        "<DEFAULT-POLICY-INLINE>",
    ];

    /// Returns a configuration template with the defaults.
    fn config_template(path: Option<PathBuf>) -> Result<String> {
        let ac = AhoCorasick::new(Self::TEMPLATE_PATTERNS)?;

        let mut p = ConfiguredStandardPolicy::new();
        p.parse_default_config()?;

        let mut default_policy_inline = Vec::new();
        p.dump(&mut default_policy_inline,
               sequoia_policy_config::DumpDefault::Template)?;
        let default_policy_inline =
            regex::Regex::new(r"(?m)^\[")?.replace_all(
                std::str::from_utf8(&default_policy_inline)?, "[policy.");

        Ok(ac.replace_all(Self::TEMPLATE, &[
            &env!("CARGO_PKG_VERSION").to_string(),
            &if let Some(path) = path {
                format!(
                    "\n\
                     # To use it, edit it to your liking and write it to\n\
                     # {}",
                    &path.display())
            } else {
                "".into()
            },
            &format!("{:?}", cli::types::Profile::default()
                     .to_possible_value().unwrap().get_name()),
            &cli::THIRD_PARTY_CERTIFICATION_VALIDITY_IN_YEARS.to_string(),
            &format!("{:?}", cli::key::CipherSuite::default().
                     to_possible_value().unwrap().get_name()),
            &format!("{:?}", cli::types::Profile::default()
                     .to_possible_value().unwrap().get_name()),
            &format!("{:?}", {
                #[cfg(feature = "network")]
                {
                    cli::network::keyserver::DEFAULT_KEYSERVERS
                }
                #[cfg(not(feature = "network"))]
                {
                    &[] as &[&str]
                }
            }),
            &format!("{:?}", {
                sequoia_keystore::sequoia_ipc::Context::configure().build()
                    .map(|c| c.lib().display().to_string())
                    .unwrap_or_else(|_| "<unknown>".into())
            }),
            &format!("{:?}", Self::global_crypto_policy_file()),
            &default_policy_inline.to_string(),
        ]))
    }

    /// Returns the default configuration in template form.
    ///
    /// All the configuration options with their defaults are
    /// commented out.
    pub fn default_template(home: Option<&Home>) -> Result<Self> {
        let template = Self::config_template(home.map(Self::file_name))?;
        let doc: DocumentMut = template.parse()
            .context("Parsing default configuration failed")?;
        Ok(Self {
            doc,
        })
    }

    /// Returns the default configuration.
    pub fn default_config(home: Option<&Home>) -> Result<Self> {
        let template = Self::config_template(home.map(Self::file_name))?;

        // Enable all defaults by commenting-in.
        let r = regex::Regex::new(r"(?m)^#([^ ])")?;
        let defaults = r.replace_all(&template, "$1");

        let doc: DocumentMut = defaults.parse()
            .context("Parsing default configuration failed")?;
        Ok(Self {
            doc,
        })
    }

    /// Returns the path of the config file.
    pub fn file_name(home: &Home) -> PathBuf {
        home.config_dir(Component::Sq).join("config.toml")
    }

    /// Reads and validates the configuration file.
    pub fn read(&mut self, home: &Home)
                -> Result<Config>
    {
        let mut config = Config::default();
        self.read_internal(home, Some(&mut config), None)?;
        Ok(config)
    }

    /// Reads and validates the configuration file.
    pub fn read_and_augment(&mut self, home: &Home) -> Result<Augmentations>
    {
        let mut augmentations = Augmentations::default();
        self.read_internal(home, None, Some(&mut augmentations))?;
        Ok(augmentations)
    }

    /// Reads and validates the configuration file, and optionally
    /// applies them to the given configuration, and optionally
    /// supplies augmentations for the help texts in the command line
    /// parser.
    fn read_internal(&mut self, home: &Home, mut config: Option<&mut Config>,
                     mut cli: Option<&mut Augmentations>)
                     -> Result<()>
    {
        let path = Self::file_name(home);
        let raw = match fs::read_to_string(&path) {
            Ok(r) => r,
            Err(e) if e.kind() == io::ErrorKind::NotFound =>
                Self::config_template(Some(path.clone()))?,
            Err(e) => return Err(anyhow::Error::from(e).context(
                format!("Reading configuration file {} failed",
                        path.display()))),
        };

        let doc: DocumentMut = raw.parse()
            .with_context(|| format!("Parsing configuration file {} failed",
                                     path.display()))?;

        apply_schema(&mut config, &mut cli, None, doc.iter(), TOP_LEVEL_SCHEMA)
            .with_context(|| format!("Parsing configuration file {} failed",
                                     path.display()))?;
        self.doc = doc;

        Ok(())
    }

    /// Writes the configuration to the disk.
    pub fn persist(&self, home: &Home) -> Result<()> {
        let path = Self::file_name(home);
        let dir = path.parent().unwrap();

        fs::create_dir_all(dir)?;

        let mut t =
            tempfile::NamedTempFile::new_in(dir)?;
        self.dump(&mut t)?;
        t.persist(path)?;

        Ok(())
    }

    /// Writes the configuration to the given writer.
    pub fn dump(&self, sink: &mut dyn io::Write) -> Result<()> {
        write!(sink, "{}", self.doc.to_string())?;
        Ok(())
    }

    /// Verifies the configuration.
    pub fn verify(&self) -> Result<()> {
        let mut config = Default::default();
        apply_schema(&mut Some(&mut config), &mut None, None, self.doc.iter(),
                     TOP_LEVEL_SCHEMA)?;
        config.policy(SystemTime::now())?;
        Ok(())
    }

    /// Augments the configuration with the effective configuration
    /// and policy.
    ///
    /// XXX: Due to the way doc.remove works, it will leave misleading
    /// comments behind.  Therefore, the resulting configuration is
    /// not suitable for dumping, but may only be used for
    /// commands::config::get.
    pub fn effective_configuration(&self, sq: &crate::Sq) -> Result<Self> {
        use std::io::Write;
        let mut raw = Vec::new();

        // First, start with our configuration, and drop most of the
        // policy with the exception of the path.
        let p = ConfiguredStandardPolicy::from_policy(sq.policy.clone());
        let mut doc = self.doc.clone();
        doc.remove("policy");

        use crate::toml_edit_tree::Node;
        let policy_path: crate::toml_edit_tree::Path
            = "policy.path".parse().unwrap();
        if let Ok(p) = self.as_item().traverse(&policy_path) {
            let p =
                p.as_atomic_value().unwrap().as_str().unwrap().to_string();
            doc.as_table_mut().insert("policy", Item::Table(
                [("path", Value::from(p))]
                    .into_iter().collect()));
        }

        write!(&mut raw, "{}", doc.to_string())?;

        // Then, augment the configuration with the effective policy.
        let mut default_policy_inline = Vec::new();
        p.dump(&mut default_policy_inline,
               sequoia_policy_config::DumpDefault::Template)?;
        let default_policy_inline =
            regex::Regex::new(r"(?m)^\[")?.replace_all(
                std::str::from_utf8(&default_policy_inline)?, "[policy.");

        write!(&mut raw, "{}", default_policy_inline)?;

        // Now, parse the resulting configuration.
        let mut doc: DocumentMut = std::str::from_utf8(&raw)?.parse()?;

        // Tweak a few settings.
        if doc.get("ui").is_none() {
            doc.as_table_mut().insert("ui".into(),
                                      Item::Table(Default::default()));
        }
        doc.get_mut("ui").expect("just created on demand")
            .set(&"hints".into(), sq.config.hints().into())?;

        // Double check that it is well-formed.
        apply_schema(&mut None, &mut None, None, doc.iter(), TOP_LEVEL_SCHEMA)?;

        Ok(Self {
            doc,
        })
    }

    /// Returns the path to the global cryptographic policy
    /// configuration file.
    pub fn global_crypto_policy_file() -> String {
        std::env::var(ConfiguredStandardPolicy::ENV_VAR)
            .unwrap_or_else(
                |_| ConfiguredStandardPolicy::CONFIG_FILE.into())
    }

    /// Returns the document tree.
    pub fn as_item(&self) -> &Item {
        self.doc.as_item()
    }

    /// Returns the mutable document tree.
    pub fn as_item_mut(&mut self) -> &mut Item {
        self.doc.as_item_mut()
    }
}

/// Validates a configuration section using a schema, and optionally
/// applies changes to the configuration and CLI augmentations.
///
/// Returns an error if a key is unknown.
///
/// known_keys better be lowercase.
fn apply_schema<'toml>(config: &mut Option<&mut Config>,
                       cli: &mut Option<&mut Augmentations>,
                       path: Option<&str>,
                       section: toml_edit::Iter<'toml>,
                       schema: Schema) -> Result<()> {
    let section = section.collect::<Vec<_>>();
    let known_keys: Vec<_> =
        schema.iter().map(|(key, _)| *key).collect();

    // Schema keys better be lowercase.
    debug_assert!(known_keys.iter().all(|&s| &s.to_lowercase() == s),
                  "keys in schema must be lowercase");

    // Schema keys better be sorted.
    debug_assert!(known_keys.windows(2).all(|v| v[0] <= v[1]),
                  "keys in schema must be sorted");
    // XXX: once [].is_sorted is stabilized:
    // debug_assert!(known_keys.is_sorted(), "keys in schema must be sorted");

    let prefix = if let Some(path) = path {
        format!("{}.", path)
    } else {
        "".to_string()
    };

    let keys: HashSet<&str> = section
        .iter().map(|(key, _value)| *key)
        .collect();

    // The set of allowed keys are the known keys, plus
    // "ignore_invalid", and the value of "ignore_invalid".
    let mut allowed_keys: Vec<&str> = known_keys.to_vec();
    if let Some(ignore) = section.iter()
        .find_map(|(k, v)| (*k == "ignore_invalid").then_some(*v))
    {
        allowed_keys.push("ignore_invalid");
        match ignore {
            Item::Value(Value::String(k)) =>
                allowed_keys.push(k.value().as_str()),
            Item::Value(Value::Array(ks)) => {
                for k in ks {
                    if let Value::String(k) = k {
                        allowed_keys.push(k.value().as_str());
                    } else {
                        Err(Error::ParseError(format!(
                            "'{}ignore_invalid' takes a string \
                             or an array of strings",
                            prefix)))?
                    }
                }
            }
            _ => {
                return Err(Error::ParseError(format!(
                    "Invalid value for '{}ignore_invalid': {}, \
                     expected a string or an array of strings",
                    prefix, ignore)).into());
            }
        }
    }

    // Now check if there are any unknown sections.
    let unknown_keys = keys
        .difference(&allowed_keys.into_iter().collect())
        .map(|s| *s)
        .collect::<Vec<_>>();
    if ! unknown_keys.is_empty() {
        return Err(Error::ParseError(format!(
            "{} has unknown keys: {}, valid keys are: {}",
            if let Some(path) = path {
                path
            } else {
                "top-level section"
            },
            unknown_keys.join(", "),
            // We don't include the keys listed in ignore_invalid.
            known_keys.join(", "))).into());
    }

    // Now validate the values.
    for (key, value) in &section {
        if let Ok(i) = schema.binary_search_by_key(key, |(k, _)| k) {
            let apply = schema[i].1;
            (apply)(config, cli, &format!("{}{}", prefix, key), value)
                .with_context(|| format!("Error validating {:?}", key))?;
        }
    }

    Ok(())
}

/// Errors used in this module.
///
/// Note: This enum cannot be exhaustively matched to allow future
/// extensions.
#[non_exhaustive]
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Parse error
    #[error("Parse error: {0}")]
    ParseError(String),

    /// A Relative Path was provided where an absolute path was expected.
    #[error("Relative path not allowed: {0}")]
    RelativePathError(PathBuf),

    /// An algorithm is not known to this crate.
    #[error("Unknown algorithm: {0}")]
    UnknownAlgorithm(String),

    #[error("Configuration item {0:?} is not a {1} but a {2}")]
    BadType(String, &'static str, &'static str),
}

impl Error {
    /// Returns an `Error::BadType` given an item.
    fn bad_item_type(path: &str, i: &Item, want_type: &'static str)
                     -> anyhow::Error
    {
        Error::BadType(path.into(), want_type, i.type_name()).into()
    }

    /// Returns an `Error::BadType` given a value.
    fn bad_value_type(path: &str, v: &Value, want_type: &'static str)
                      -> anyhow::Error
    {
        Error::BadType(path.into(), want_type, v.type_name()).into()
    }
}

/// A function that validates a node in the configuration tree with
/// the given path, and optionally makes changes to the configuration
/// and CLI augmentations.
type Applicator = fn(&mut Option<&mut Config>, &mut Option<&mut Augmentations>,
                     &str, &Item)
                     -> Result<()>;

/// Ignores a node.
fn apply_nop(_: &mut Option<&mut Config>, _: &mut Option<&mut Augmentations>,
             _: &str, _: &Item)
             -> Result<()>
{
    Ok(())
}

/// A [`Schema`] maps keys to [`Applicator`]s.
type Schema = &'static [(&'static str, Applicator)];

/// Schema for the toplevel.
const TOP_LEVEL_SCHEMA: Schema = &[
    ("encrypt", apply_encrypt),
    ("key", apply_key),
    ("network", apply_network),
    ("pki", apply_pki),
    ("policy", apply_policy),
    ("servers", apply_servers),
    ("sign", apply_sign),
    ("ui", apply_ui),
];

/// Schema for the `ui` section.
const UI_SCHEMA: Schema = &[
    ("hints", apply_ui_hints),
    ("verbosity", apply_ui_verbosity),
];

/// Validates the `ui` section.
fn apply_ui(config: &mut Option<&mut Config>, cli: &mut Option<&mut Augmentations>,
            path: &str, item: &Item)
            -> Result<()>
{
    let section = item.as_table_like()
        .ok_or_else(|| Error::bad_item_type(path, item, "table"))?;
    apply_schema(config, cli, Some(path), section.iter(), UI_SCHEMA)?;
    Ok(())
}

/// Validates the `ui.hints` value.
fn apply_ui_hints(config: &mut Option<&mut Config>,
                  _cli: &mut Option<&mut Augmentations>,
                  path: &str, item: &Item)
                  -> Result<()>
{
    let s = item.as_bool()
        .ok_or_else(|| Error::bad_item_type(path, item, "bool"))?;

    if let Some(config) = config {
        config.hints = Some(s);
    }

    Ok(())
}

/// Validates the `ui.verbosity` value.
fn apply_ui_verbosity(config: &mut Option<&mut Config>,
                      cli: &mut Option<&mut Augmentations>,
                      path: &str, item: &Item)
                      -> Result<()>
{
    let s = item.as_str()
        .ok_or_else(|| Error::bad_item_type(path, item, "string"))?;

    let mut verbose = false;
    let mut quiet = false;
    match s {
        "default" => (),
        "verbose" => verbose = true,
        "quiet" => quiet = true,
        _ => return Err(anyhow::anyhow!("verbosity must be either \
                                         \"default\", \
                                         \"verbose\", \
                                         or \"quiet\"")),
    };

    if let Some(config) = config {
        config.verbose = verbose;
        config.quiet = quiet;
    }

    if let Some(cli) = cli {
        if verbose {
            cli.insert("ui.verbose", "verbose".into());
        }

        if quiet {
            cli.insert("ui.quiet", "quiet".into());
        }
    }

    Ok(())
}

/// Schema for the `encrypt` section.
const ENCRYPT_SCHEMA: Schema = &[
    ("for-self", apply_encrypt_for_self),
    ("profile", apply_encrypt_profile),
];

/// Validates the `encrypt` section.
fn apply_encrypt(config: &mut Option<&mut Config>, cli: &mut Option<&mut Augmentations>,
                 path: &str, item: &Item)
                 -> Result<()>
{
    let section = item.as_table_like()
        .ok_or_else(|| Error::bad_item_type(path, item, "table"))?;
    apply_schema(config, cli, Some(path), section.iter(), ENCRYPT_SCHEMA)?;
    Ok(())
}

/// Validates the `encrypt.for-self` value.
fn apply_encrypt_for_self(config: &mut Option<&mut Config>,
                          cli: &mut Option<&mut Augmentations>,
                          path: &str, item: &Item)
                          -> Result<()>
{
    let list = item.as_array()
        .ok_or_else(|| Error::bad_item_type(path, item, "array"))?;

    let mut strs = Vec::new();
    let mut values = BTreeSet::default();
    for (i, server) in list.iter().enumerate() {
        let s = server.as_str()
            .ok_or_else(|| Error::bad_value_type(&format!("{}.{}", path, i),
                                                 server, "string"))?;

        strs.push(s);
        values.insert(s.parse::<Fingerprint>()?);
    }

    if let Some(cli) = cli {
        cli.insert("encrypt.for-self", strs.join(" "));
    }

    if let Some(config) = config {
        config.encrypt_for_self = values;
    }

    Ok(())
}

/// Validates the `key.generate.profile` value.
fn apply_encrypt_profile(config: &mut Option<&mut Config>,
                         cli: &mut Option<&mut Augmentations>,
                         path: &str, item: &Item)
                         -> Result<()>
{
    let s = item.as_str()
        .ok_or_else(|| Error::bad_item_type(path, item, "string"))?;
    let v = cli::types::Profile::from_str(s, false)
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    if let Some(config) = config {
        config.encrypt_profile = Some(v.clone());
    }

    if let Some(cli) = cli {
        cli.insert(
            "encrypt.profile",
            v.to_possible_value().expect("just validated").get_name().into());
    }

    Ok(())
}

/// Schema for the `sign` section.
const SIGN_SCHEMA: Schema = &[
    ("signer-self", apply_sign_signer_self),
];

/// Validates the `sign` section.
fn apply_sign(config: &mut Option<&mut Config>,
              cli: &mut Option<&mut Augmentations>,
              path: &str, item: &Item)
              -> Result<()>
{
    let section = item.as_table_like()
        .ok_or_else(|| Error::bad_item_type(path, item, "table"))?;
    apply_schema(config, cli, Some(path), section.iter(), SIGN_SCHEMA)?;
    Ok(())
}

/// Validates the `sign.signer-self` value.
fn apply_sign_signer_self(config: &mut Option<&mut Config>,
                          cli: &mut Option<&mut Augmentations>,
                          path: &str, item: &Item)
                          -> Result<()>
{
    let list = item.as_array()
        .ok_or_else(|| Error::bad_item_type(path, item, "array"))?;

    let mut strs = Vec::new();
    let mut values = BTreeSet::default();
    for (i, server) in list.iter().enumerate() {
        let s = server.as_str()
            .ok_or_else(|| Error::bad_value_type(&format!("{}.{}", path, i),
                                                 server, "string"))?;

        strs.push(s);
        values.insert(s.parse::<Fingerprint>()?);
    }

    if let Some(cli) = cli {
        cli.insert("sign.signer-self", strs.join(" "));
    }

    if let Some(config) = config {
        config.sign_signer_self = values;
    }

    Ok(())
}

/// Schema for the `pki` section.
const PKI_SCHEMA: Schema = &[
    ("vouch", apply_pki_vouch),
];

/// Validates the `pki` section.
fn apply_pki(config: &mut Option<&mut Config>,
              cli: &mut Option<&mut Augmentations>,
              path: &str, item: &Item)
              -> Result<()>
{
    let section = item.as_table_like()
        .ok_or_else(|| Error::bad_item_type(path, item, "table"))?;
    apply_schema(config, cli, Some(path), section.iter(), PKI_SCHEMA)?;
    Ok(())
}

/// Schema for the `pki.vouch` section.
const PKI_VOUCH_SCHEMA: Schema = &[
    ("certifier-self", apply_pki_vouch_certifier_self),
    ("expiration", apply_pki_vouch_expiration),
];

/// Validates the `pki.vouch` section.
fn apply_pki_vouch(config: &mut Option<&mut Config>,
              cli: &mut Option<&mut Augmentations>,
              path: &str, item: &Item)
              -> Result<()>
{
    let section = item.as_table_like()
        .ok_or_else(|| Error::bad_item_type(path, item, "table"))?;
    apply_schema(config, cli, Some(path), section.iter(), PKI_VOUCH_SCHEMA)?;
    Ok(())
}

/// Validates the `pki.vouch.certifier-self` value.
fn apply_pki_vouch_certifier_self(config: &mut Option<&mut Config>,
                                  cli: &mut Option<&mut Augmentations>,
                                  path: &str, item: &Item)
                                  -> Result<()>
{
    let s = item.as_str()
        .ok_or_else(|| Error::bad_item_type(path, item, "string"))?;

    let fp = s.parse::<Fingerprint>()?;

    if let Some(cli) = cli {
        cli.insert("pki.vouch.certifier-self", fp.to_string());
    }

    if let Some(config) = config {
        config.pki_vouch_certifier_self = Some(fp);
    }

    Ok(())
}

/// Validates the `pki.vouch.expiration` value.
fn apply_pki_vouch_expiration(config: &mut Option<&mut Config>,
                              cli: &mut Option<&mut Augmentations>,
                              path: &str, item: &Item)
                              -> Result<()>
{
    let s = item.as_str()
        .ok_or_else(|| Error::bad_item_type(path, item, "string"))?;

    let v = s.parse::<cli::types::Expiration>()?;

    if let Some(cli) = cli {
        cli.insert("pki.vouch.expiration", v.to_string());
    }

    if let Some(config) = config {
        config.pki_vouch_expiration = Some(v);
    }

    Ok(())
}

/// Schema for the `key` section.
const KEY_SCHEMA: Schema = &[
    ("generate", apply_key_generate),
];

/// Validates the `key` section.
fn apply_key(config: &mut Option<&mut Config>, cli: &mut Option<&mut Augmentations>,
                 path: &str, item: &Item)
                 -> Result<()>
{
    let section = item.as_table_like()
        .ok_or_else(|| Error::bad_item_type(path, item, "table"))?;
    apply_schema(config, cli, Some(path), section.iter(), KEY_SCHEMA)?;
    Ok(())
}

/// Schema for the `key.generate` section.
const KEY_GENERATE_SCHEMA: Schema = &[
    ("cipher-suite", apply_key_generate_cipher_suite),
    ("profile", apply_key_generate_profile),
];

/// Validates the `key.generate` section.
fn apply_key_generate(config: &mut Option<&mut Config>,
                      cli: &mut Option<&mut Augmentations>,
                      path: &str, item: &Item)
                      -> Result<()>
{
    let section = item.as_table_like()
        .ok_or_else(|| Error::bad_item_type(path, item, "table"))?;
    apply_schema(config, cli, Some(path), section.iter(), KEY_GENERATE_SCHEMA)?;
    Ok(())
}

/// Validates the `key.generate.cipher-suite` value.
fn apply_key_generate_cipher_suite(config: &mut Option<&mut Config>,
                                   cli: &mut Option<&mut Augmentations>,
                                   path: &str, item: &Item)
                                   -> Result<()>
{
    let s = item.as_str()
        .ok_or_else(|| Error::bad_item_type(path, item, "string"))?;
    let v = cli::key::CipherSuite::from_str(s, false)
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    if let Some(config) = config {
        config.cipher_suite = Some(v.as_ciphersuite());
    }

    if let Some(cli) = cli {
        cli.insert(
            "key.generate.cipher-suite",
            v.to_possible_value().expect("just validated").get_name().into());
    }

    Ok(())
}

/// Validates the `key.generate.profile` value.
fn apply_key_generate_profile(config: &mut Option<&mut Config>,
                              cli: &mut Option<&mut Augmentations>,
                              path: &str, item: &Item)
                              -> Result<()>
{
    let s = item.as_str()
        .ok_or_else(|| Error::bad_item_type(path, item, "string"))?;
    let v = cli::types::Profile::from_str(s, false)
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    if let Some(config) = config {
        config.key_generate_profile = Some(v.clone());
    }

    if let Some(cli) = cli {
        cli.insert(
            "key.generate.profile",
            v.to_possible_value().expect("just validated").get_name().into());
    }

    Ok(())
}

/// Schema for the `network` section.
const NETWORK_SCHEMA: Schema = &[
    ("keyservers", apply_network_keyservers),
    ("search", apply_network_search),
];

/// Validates the `network` section.
fn apply_network(config: &mut Option<&mut Config>, cli: &mut Option<&mut Augmentations>,
                 path: &str, item: &Item)
                 -> Result<()>
{
    let section = item.as_table_like()
        .ok_or_else(|| Error::bad_item_type(path, item, "table"))?;
    apply_schema(config, cli, Some(path), section.iter(), NETWORK_SCHEMA)?;
    Ok(())
}

/// Validates the `network.keyservers` value.
fn apply_network_keyservers(config: &mut Option<&mut Config>,
                            cli: &mut Option<&mut Augmentations>,
                            path: &str, item: &Item)
                            -> Result<()>
{
    let list = item.as_array()
        .ok_or_else(|| Error::bad_item_type(path, item, "array"))?;

    let mut servers_str = Vec::new();
    let mut servers_url = Vec::new();
    for (i, server) in list.iter().enumerate() {
        let server_str = server.as_str()
            .ok_or_else(|| Error::bad_value_type(&format!("{}.{}", path, i),
                                                 server, "string"))?;

        let url = Url::parse(server_str)?;
        let s = url.scheme();
        match s {
            "hkp" => (),
            "hkps" => (),
            _ => return Err(anyhow::anyhow!(
                "must be a hkp:// or hkps:// URL: {}", url)),
        }

        servers_str.push(server_str);
        servers_url.push(url);
    }

    if let Some(cli) = cli {
        cli.insert("network.keyserver.servers", servers_str.join(" "));
    }

    if let Some(config) = config {
        config.key_servers = Some(servers_url);
    }

    Ok(())
}

/// Schema for the `network.search` section.
const NETWORK_SEARCH_SCHEMA: Schema = &[
    ("iterations", apply_network_search_iterations),
    ("use-dane", apply_network_search_use_dane),
    ("use-wkd", apply_network_search_use_wkd),
];

/// Validates the `network.search` section.
fn apply_network_search(config: &mut Option<&mut Config>,
                        cli: &mut Option<&mut Augmentations>,
                        path: &str, item: &Item)
                        -> Result<()>
{
    let section = item.as_table_like()
        .ok_or_else(|| Error::bad_item_type(path, item, "table"))?;
    apply_schema(config, cli, Some(path), section.iter(),
                 NETWORK_SEARCH_SCHEMA)?;
    Ok(())
}

/// Validates the `network.search.iterations` value.
fn apply_network_search_iterations(config: &mut Option<&mut Config>,
                                   cli: &mut Option<&mut Augmentations>,
                                   path: &str, item: &Item)
                                   -> Result<()>
{
    let s = item.as_integer()
        .ok_or_else(|| Error::bad_item_type(path, item, "integer"))?;

    if let Some(config) = config {
        if s == 0 {
            return Err(anyhow::anyhow!("value must be at least 1"));
        }

        config.network_search_iterations = Some(
            s.try_into()
                .map_err(|_| anyhow::anyhow!("value must not exceed 255"))?
        );
    }

    if let Some(cli) = cli {
        cli.insert("network.search.iterations", s.to_string());
    }

    Ok(())
}

/// Validates the `network.search.use-dane` value.
fn apply_network_search_use_dane(config: &mut Option<&mut Config>,
                                 cli: &mut Option<&mut Augmentations>,
                                 path: &str, item: &Item)
                                 -> Result<()>
{
    let s = item.as_bool()
        .ok_or_else(|| Error::bad_item_type(path, item, "bool"))?;

    if let Some(config) = config {
        config.network_search_use_dane = Some(s);
    }

    if let Some(cli) = cli {
        cli.insert("network.search.use-dane", s.to_string());
    }

    Ok(())
}

/// Validates the `network.search.use-wkd` value.
fn apply_network_search_use_wkd(config: &mut Option<&mut Config>,
                                cli: &mut Option<&mut Augmentations>,
                                path: &str, item: &Item)
                                -> Result<()>
{
    let s = item.as_bool()
        .ok_or_else(|| Error::bad_item_type(path, item, "bool"))?;

    if let Some(config) = config {
        config.network_search_use_wkd = Some(s);
    }

    if let Some(cli) = cli {
        cli.insert("network.search.use-wkd", s.to_string());
    }

    Ok(())
}

/// Schema for the `policy` section.
const POLICY_SCHEMA: Schema = &[
    ("aead_algorithms", apply_nop),
    ("asymmetric_algorithms", apply_nop),
    ("hash_algorithms", apply_nop),
    ("packets", apply_nop),
    ("path", apply_policy_path),
    ("symmetric_algorithms", apply_nop),
];

/// Validates the `policy` section.
fn apply_policy(config: &mut Option<&mut Config>,
                cli: &mut Option<&mut Augmentations>,
                path: &str, item: &Item)
                -> Result<()>
{
    let section = item.as_table_like()
        .ok_or_else(|| Error::bad_item_type(path, item, "table"))?;
    apply_schema(config, cli, Some(path), section.iter(), POLICY_SCHEMA)?;

    if let Some(config) = config {
        // Extract the inline policy.

        // XXX: This doesn't work because toml_edit bug
        // https://github.com/toml-rs/toml/issues/785
        //
        //let table = section.iter().collect::<Table>();
        //
        // Instead, we have to use a workaround:
        let mut table = Table::new();
        section.iter().for_each(|(k, v)| { table.insert(k, v.clone()); });

        let mut inline = DocumentMut::from(table);
        inline.remove("path");
        config.policy_inline = Some(inline.to_string().into_bytes());
    }

    Ok(())
}

/// Validates the `policy.path` value.
fn apply_policy_path(config: &mut Option<&mut Config>,
                     _: &mut Option<&mut Augmentations>,
                     path: &str, item: &Item)
                     -> Result<()>
{
    let path = item.as_str()
        .ok_or_else(|| Error::bad_item_type(path, item, "string"))?;

    if let Some(config) = config {
        config.policy_path = Some(path.into());
    }

    Ok(())
}

/// Schema for the `servers` section.
const SERVERS_SCHEMA: Schema = &[
    ("path", apply_servers_path),
];

/// Validates the `servers` section.
fn apply_servers(config: &mut Option<&mut Config>, cli: &mut Option<&mut Augmentations>,
                 path: &str, item: &Item)
                 -> Result<()>
{
    let section = item.as_table_like()
        .ok_or_else(|| Error::bad_item_type(path, item, "table"))?;
    apply_schema(config, cli, Some(path), section.iter(), SERVERS_SCHEMA)?;
    Ok(())
}

/// Validates the `servers.path` value.
fn apply_servers_path(config: &mut Option<&mut Config>,
                      _: &mut Option<&mut Augmentations>,
                      path: &str, item: &Item)
                      -> Result<()>
{
    let path = item.as_str()
        .ok_or_else(|| Error::bad_item_type(path, item, "string"))?;

    if let Some(config) = config {
        config.servers_path = Some(path.into());
    }

    Ok(())
}
