use std::borrow::Borrow;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::SystemTime;

use typenum::Unsigned;

use anyhow::anyhow;
use anyhow::Context as _;

use once_cell::sync::OnceCell;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::crypto;
use openpgp::crypto::Password;
use openpgp::Fingerprint;
use openpgp::KeyHandle;
use openpgp::Result;
use openpgp::cert::prelude::*;
use openpgp::cert::raw::RawCertParser;
use openpgp::packet::key::PublicParts;
use openpgp::packet::prelude::*;
use openpgp::parse::Parse;
use openpgp::policy::Policy;
use openpgp::policy::StandardPolicy as P;
use openpgp::policy::NullPolicy;
use openpgp::types::KeyFlags;
use openpgp::types::RevocationStatus;
use openpgp::types::RevocationType;

use sequoia_cert_store as cert_store;
use cert_store::LazyCert;
use cert_store::Store;
use cert_store::store::MergePublicCollectStats;
use cert_store::store::StoreError;
use cert_store::store::StoreUpdate;
use cert_store::store::UserIDQueryParams;

use sequoia_wot as wot;
use wot::store::Store as _;

use sequoia_keystore as keystore;
use keystore::Protection;

use crate::cli;
use crate::cli::types::CertDesignators;
use crate::cli::types::FileStdinOrKeyHandle;
use crate::cli::types::KeyDesignators;
use crate::cli::types::SpecialName;
use crate::cli::types::StdinWarning;
use crate::cli::types::cert_designator;
use crate::cli::types::key_designator;
use crate::cli::types::paths::StateDirectory;
use crate::common::password;
use crate::common::ui;
use crate::output::hint::Hint;
use crate::output::import::{ImportStats, ImportStatus};
use crate::PreferredUserID;
use crate::print_error_chain;

const TRACE: bool = false;

pub static NULL_POLICY: NullPolicy = unsafe { NullPolicy::new() };

/// Flags for Sq::get_keys and related functions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GetKeysOptions {
    /// Don't ignore keys that are not alive.
    AllowNotAlive,
    /// Don't ignore keys that are not revoke.
    AllowRevoked,
    /// Use the NULL Policy.
    NullPolicy,
}

/// Flag for Sq::get_keys and related function.
enum KeyType {
    /// Only consider primary key.
    Primary,
    /// Only consider keys that have at least one of the specified
    /// capabilities.
    KeyFlags(KeyFlags),
}

/// The degree to which a binding needs to be authenticated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustThreshold {
    /// The binding must be fully authenticated.
    Full = wot::FULLY_TRUSTED as isize,
    /// The binding must be minimally authenticated (>= 1 out of 120).
    Minimal = 1,
    /// The binding doesn't need to be authenticated.
    YOLO = 0,
}

impl From<TrustThreshold> for usize {
    fn from(a: TrustThreshold) -> usize {
        a as isize as usize
    }
}

impl From<&TrustThreshold> for usize {
    fn from(a: &TrustThreshold) -> usize {
        *a as isize as usize
    }
}

impl std::fmt::Display for TrustThreshold {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", usize::from(self))
    }
}


// A shorthand for our store type.
type WotStore<'store, 'rstore>
    = wot::store::CertStore<'store, 'rstore, cert_store::CertStore<'store>>;

pub struct Sq<'store, 'rstore>
    where 'store: 'rstore
{
    pub config_file: crate::config::ConfigFile,
    pub config: crate::config::Config,

    /// Overwrite existing files.
    pub overwrite: bool,

    /// Prevent any kind of interactive prompting.
    pub batch: bool,

    pub time: SystemTime,
    pub time_is_now: bool,
    pub policy: &'rstore P<'rstore>,
    pub policy_as_of: SystemTime,
    pub home: Option<sequoia_directories::Home>,
    pub cert_store_path: Option<StateDirectory>,
    pub keyrings: Vec<PathBuf>,
    // Map from key fingerprint to cert fingerprint and the key.
    pub keyring_tsks: OnceCell<BTreeMap<
            Fingerprint,
        (Fingerprint, Key<key::PublicParts, key::UnspecifiedRole>)>>,

    /// This will be set if the cert store has not been disabled, OR
    /// --keyring is passed.
    pub cert_store: OnceCell<WotStore<'store, 'rstore>>,

    // The value of --trust-root.
    pub trust_roots: Vec<Fingerprint>,
    // The local trust root, as set in the cert store.
    pub trust_root_local: OnceCell<Option<Fingerprint>>,

    // The key store.
    pub key_store_path: Option<StateDirectory>,
    pub key_store: OnceCell<Mutex<keystore::Keystore>>,

    /// A password cache.  When encountering a locked key, we first
    /// consult the password cache.  The passwords are only tried if
    /// it is safe.  That is, the passwords are only tried if we are
    /// sure that the key is not protected by a retry counter.  If the
    /// password cache doesn't contain the correct password, or the
    /// key is protected by a retry counter, the user is prompted to
    /// unlock the key.  The correct password is added to the cache.
    pub password_cache: Mutex<Vec<Password>>,
}

impl<'store: 'rstore, 'rstore> Sq<'store, 'rstore> {
    /// Be verbose.
    pub fn verbose(&self) -> bool {
        self.config.verbose()
    }

    /// Be quiet.
    pub fn quiet(&self) -> bool {
        self.config.quiet()
    }

    /// Returns whether the cert store is disabled.
    fn no_rw_cert_store(&self) -> bool {
        self.cert_store_path.as_ref()
            .map(|s| s.is_none())
            .unwrap_or(self.home.is_none())
    }

    /// Returns whether the key store is disabled.
    fn no_key_store(&self) -> bool {
        self.key_store_path.as_ref()
            .map(|s| s.is_none())
            .unwrap_or(self.home.is_none())
    }

    /// Returns the cert store's base directory, if it is enabled.
    pub fn cert_store_base(&self) -> Option<PathBuf> {
        let default = || if let Ok(path) = std::env::var("PGP_CERT_D") {
            Some(PathBuf::from(path))
        } else {
            self.home.as_ref()
                .map(|h| h.data_dir(sequoia_directories::Component::CertD))
        };

        if let Some(state) = self.cert_store_path.as_ref() {
            match state {
                StateDirectory::Absolute(p) => Some(p.clone()),
                StateDirectory::Default => default(),
                StateDirectory::None => None,
            }
        } else {
            default()
        }
    }

    /// Returns the cert store.
    ///
    /// If the cert store is disabled, returns `Ok(None)`.  If it is not yet
    /// open, opens it.
    pub fn cert_store(&self) -> Result<Option<&WotStore<'store, 'rstore>>> {
        if self.no_rw_cert_store()
            && self.keyrings.is_empty()
        {
            // The cert store is disabled.
            return Ok(None);
        }

        if let Some(cert_store) = self.cert_store.get() {
            // The cert store is already initialized, return it.
            return Ok(Some(cert_store));
        }

        let create_dirs = |path: &Path| -> Result<()> {
            use std::fs::DirBuilder;

            let mut b = DirBuilder::new();
            b.recursive(true);

            // Create the parent with the normal umask.
            if let Some(parent) = path.parent() {
                // Note: since recursive is turned on, it is not an
                // error if the directory exists, which is exactly
                // what we want.
                b.create(parent)
                    .with_context(|| {
                        format!("Creating the directory {:?}", parent)
                    })?;
            }

            // Create path with more restrictive permissions.
            platform!{
                unix => {
                    use std::os::unix::fs::DirBuilderExt;
                    b.mode(0o700);
                },
                windows => {
                },
            }

            b.create(path)
                .with_context(|| {
                    format!("Creating the directory {:?}", path)
                })?;

            Ok(())
        };

        // We need to initialize the cert store.
        let mut cert_store = if ! self.no_rw_cert_store() {
            // Open the cert-d.

            let path = self.cert_store_base()
                .expect("just checked that it is configured");

            create_dirs(&path)
                .and_then(|_| cert_store::CertStore::open(&path))
                .with_context(|| {
                    format!("While opening the certificate store at {:?}",
                            &path)
                })?
        } else {
            cert_store::CertStore::empty()
        };

        let keyring = cert_store::store::Certs::empty();
        let mut tsks = BTreeMap::new();
        let mut error = None;
        for filename in self.keyrings.iter() {
            let f = std::fs::File::open(filename)
                .with_context(|| format!("Open {:?}", filename))?;
            let parser = RawCertParser::from_reader(f)
                .with_context(|| format!("Parsing {:?}", filename))?;

            for cert in parser {
                match cert {
                    Ok(cert) => {
                        for key in cert.keys() {
                            if key.has_secret() {
                                tsks.insert(
                                    key.fingerprint(),
                                    (cert.fingerprint(), key.clone()));
                            }
                        }

                        keyring.update(Arc::new(cert.into()))
                            .expect("implementation doesn't fail");
                    }
                    Err(err) => {
                        eprint!("Parsing certificate in {:?}: {}",
                                filename, err);
                        error = Some(err);
                    }
                }
            }
        }

        self.keyring_tsks.set(tsks).expect("uninitialized");

        if let Some(err) = error {
            return Err(err).context("Parsing keyrings");
        }

        cert_store.add_backend(
            Box::new(keyring),
            cert_store::AccessMode::Always);

        // Sync certs from GnuPG's state if we are using the user's
        // default home directory.
        if self.home.as_ref().map(|h| h.is_default_location())
            .unwrap_or(false)
            && std::env::var("GNUPGHOME").is_err()
        {
            if let Err(e) = crate::compat::sync_from_gnupg(self, &cert_store) {
                self.info(format_args!(
                    "Syncing state from GnuPG failed: {}", e));
            }
        }

        let cert_store = WotStore::from_store(
            cert_store, self.policy, self.time);

        let _ = self.cert_store.set(cert_store);

        Ok(Some(self.cert_store.get().expect("just configured")))
    }

    fn no_cert_store_err() -> clap::Error {
        clap::Error::raw(clap::error::ErrorKind::ArgumentConflict,
                         "Operation requires a certificate store, \
                          but the certificate store is disabled")
    }

    /// Returns the cert store.
    ///
    /// If the cert store is disabled, returns an error.
    pub fn cert_store_or_else(&self) -> Result<&WotStore<'store, 'rstore>> {
        self.cert_store().and_then(|cert_store| cert_store.ok_or_else(|| {
            Self::no_cert_store_err().into()
        }))
    }

    /// Returns a mutable reference to the cert store.
    ///
    /// If the cert store is disabled, returns None.  If it is not yet
    /// open, opens it.
    pub fn cert_store_mut(&mut self)
        -> Result<Option<&mut WotStore<'store, 'rstore>>>
    {
        if self.no_rw_cert_store() {
            return Err(Self::no_cert_store_err().into());
        }

        // self.cert_store() will do any required initialization, but
        // it will return an immutable reference.
        self.cert_store()?;
        Ok(self.cert_store.get_mut())
    }

    /// Returns a mutable reference to the cert store.
    ///
    /// If the cert store is disabled, returns an error.
    #[allow(unused)]
    pub fn cert_store_mut_or_else(&mut self)
        -> Result<&mut WotStore<'store, 'rstore>>
    {
        self.cert_store_mut().and_then(|cert_store| cert_store.ok_or_else(|| {
            Self::no_cert_store_err().into()
        }))
    }

    /// Returns a reference to the underlying certificate directory,
    /// if it is configured.
    ///
    /// If the cert direcgory is disabled, returns an error.
    pub fn certd_or_else(&self)
        -> Result<&cert_store::store::certd::CertD<'store>>
    {
        const NO_CERTD_ERR: &str =
            "A local trust root and other special certificates are \
             only available when using an OpenPGP certificate \
             directory";

        let cert_store = self.cert_store_or_else()
            .with_context(|| NO_CERTD_ERR.to_string())?;

        cert_store.certd()
            .ok_or_else(|| anyhow::anyhow!(NO_CERTD_ERR))
    }


    /// Returns a web-of-trust query builder.
    ///
    /// The trust roots are already set appropriately.
    pub fn wot_query(&self)
        -> Result<wot::NetworkBuilder<&WotStore<'store, 'rstore>>>
    {
        let cert_store = self.cert_store_or_else()?;
        let network = wot::NetworkBuilder::rooted(cert_store,
                                                  &*self.trust_roots());
        Ok(network)
    }

    /// Returns the key store's path.
    ///
    /// If the key store is disabled, returns `Ok(None)`.
    pub fn key_store_path(&self) -> Result<Option<PathBuf>> {
        let default = || {
            Ok(self.home.as_ref()
               .map(|h| h.data_dir(sequoia_directories::Component::Keystore)))
        };

        if let Some(dir) = self.key_store_path.as_ref() {
            match dir {
                StateDirectory::Absolute(p) => Ok(Some(p.clone())),
                StateDirectory::Default => default(),
                StateDirectory::None => Ok(None),
            }
        } else {
            default()
        }
    }

    fn no_key_store_err() -> clap::Error {
        clap::Error::raw(clap::error::ErrorKind::ArgumentConflict,
                         "Operation requires a key store, \
                          but the key store is disabled")
    }

    /// Returns the key store's path.
    ///
    /// If the key store is disabled, returns an error.
    pub fn key_store_path_or_else(&self) -> Result<PathBuf> {
        if self.no_key_store() {
            Err(Self::no_key_store_err().into())
        } else {
            self.key_store_path()?
                .ok_or_else(|| {
                    Self::no_key_store_err().into()
                })
        }
    }

    /// Returns the key store.
    ///
    /// If the key store is disabled, returns `Ok(None)`.  If it is not yet
    /// open, opens it.
    pub fn key_store(&self) -> Result<Option<&Mutex<keystore::Keystore>>> {
        if self.no_key_store() {
            return Ok(None);
        }

        self.key_store
            .get_or_try_init(|| {
                let mut c = keystore::Context::configure()
                    .home(self.key_store_path_or_else()?);

                if let Some(p) = self.config.servers_path() {
                    c = c.lib(p);
                }

                let c = c.build()?;
                let ks = keystore::Keystore::connect(&c)
                    .context("Connecting to key store")?;

                Ok(Mutex::new(ks))
            })
            .map(Some)
    }

    /// Returns the key store.
    ///
    /// If the key store is disabled, returns an error.
    pub fn key_store_or_else(&self) -> Result<&Mutex<keystore::Keystore>> {
        self.key_store().and_then(|key_store| key_store.ok_or_else(|| {
            Self::no_key_store_err().into()
        }))
    }

    /// Returns the secret keys found in any specified keyrings.
    pub fn keyring_tsks(&self)
        -> Result<&BTreeMap<Fingerprint,
                            (Fingerprint, Key<key::PublicParts, key::UnspecifiedRole>)>>
    {
        if let Some(keyring_tsks) = self.keyring_tsks.get() {
            Ok(keyring_tsks)
        } else {
            // This also initializes keyring_tsks.
            self.cert_store()?;

            // If something went wrong, we just set it to an empty
            // map.
            Ok(self.keyring_tsks.get_or_init(|| BTreeMap::new()))
        }
    }

    /// Looks up an identifier.
    ///
    /// This matches on both the primary key and the subkeys.
    ///
    /// If `keyflags` is not `None`, then only returns certificates
    /// where the matching key has at least one of the specified key
    /// flags.  If `or_by_primary` is set, then certificates with the
    /// specified key handle and a subkey with the specified flags
    /// also match.
    ///
    /// If `allow_ambiguous` is true, then all matching certificates
    /// are returned.  Otherwise, if an identifier matches multiple
    /// certificates an error is returned.
    ///
    /// An error is also returned if any of the identifiers does not
    /// match at least one certificate.
    pub fn lookup<'a, I>(&self, handles: I,
                         keyflags: Option<KeyFlags>,
                         or_by_primary: bool,
                         allow_ambiguous: bool)
        -> Result<Vec<Cert>>
    where I: IntoIterator,
          I::Item: Into<FileStdinOrKeyHandle>,
    {
        self.lookup_with_policy(
            handles, keyflags, or_by_primary, allow_ambiguous,
            self.policy, self.time)
    }

    /// Looks up an identifier.
    ///
    /// Like [`Sq::lookup`], but uses an alternate policy and an
    /// alternate reference time.
    pub fn lookup_with_policy<'a, I>(&self, handles: I,
                                     keyflags: Option<KeyFlags>,
                                     or_by_primary: bool,
                                     allow_ambiguous: bool,
                                     policy: &dyn Policy,
                                     time: SystemTime)
        -> Result<Vec<Cert>>
    where I: IntoIterator,
          I::Item: Into<FileStdinOrKeyHandle>,
    {
        let mut results = Vec::new();

        for handle in handles {
            let (kh, mut certs) = match handle.into() {
                FileStdinOrKeyHandle::FileOrStdin(file) => {
                    let br = file.open("an OpenPGP certificate")?;
                    let cert = Cert::from_buffered_reader(br)?;
                    (cert.key_handle(), vec![ cert ])
                }
                FileStdinOrKeyHandle::KeyHandle(kh) => {
                    let certs = self.cert_store_or_else()?
                        .lookup_by_cert_or_subkey(&kh)
                        .with_context(|| {
                            format!("Failed to load {} from certificate store", kh)
                        })?
                        .into_iter()
                        .filter_map(|cert| {
                            match cert.to_cert() {
                                Ok(cert) => Some(cert.clone()),
                                Err(err) => {
                                    let err = err.context(
                                        format!("Failed to parse {} as loaded \
                                                 from certificate store", kh));
                                    print_error_chain(&err);
                                    None
                                }
                            }
                        })
                        .collect::<Vec<Cert>>();

                    (kh.clone(), certs)
                }
            };

            if let Some(keyflags) = keyflags.as_ref() {
                certs.retain(|cert| {
                    let vc = match cert.with_policy(policy, time)
                    {
                        Ok(vc) => vc,
                        Err(err) => {
                            let err = err.context(
                                format!("{} is not valid according \
                                         to the current policy, ignoring",
                                        kh));
                            print_error_chain(&err);
                            return false;
                        }
                    };

                    let checked_id = or_by_primary
                        && vc.cert().key_handle().aliases(&kh);

                    for ka in vc.keys() {
                        if checked_id || ka.key().key_handle().aliases(&kh) {
                            if &ka.key_flags().unwrap_or(KeyFlags::empty())
                                & keyflags
                                != KeyFlags::empty()
                            {
                                return true;
                            }
                        }
                    }

                    if checked_id {
                        weprintln!("Error: {} does not have a key with \
                                    the required capabilities ({:?})",
                                   cert.keyid(), keyflags);
                    } else {
                        weprintln!("Error: The subkey {} (cert: {}) \
                                    does not have the required capabilities \
                                    ({:?})",
                                   kh, cert.keyid(), keyflags);
                    }
                    return false;
                })
            }

            if ! allow_ambiguous && certs.len() > 1 {
                return Err(anyhow::anyhow!(
                    "{} is ambiguous; it matches: {}",
                    kh,
                    certs.into_iter()
                        .map(|cert| cert.fingerprint().to_string())
                        .collect::<Vec<String>>()
                        .join(", ")));
            }

            if certs.len() == 0 {
                return Err(StoreError::NotFound(kh.clone()).into());
            }

            results.extend(certs);
        }

        Ok(results)
    }

    /// Looks up a certificate.
    ///
    /// Like [`Sq::lookup`], but looks up a certificate, which must be
    /// uniquely identified by `handle` and `keyflags`.
    pub fn lookup_one<H>(&self, handle: H,
                      keyflags: Option<KeyFlags>, or_by_primary: bool)
        -> Result<Cert>
    where H: Into<FileStdinOrKeyHandle>
    {
        self.lookup_one_with_policy(handle, keyflags, or_by_primary,
                                    self.policy, self.time)
    }

    /// Looks up a certificate.
    ///
    /// Like [`Sq::lookup_one_with_policy`], but uses an alternate
    /// policy and an alternate reference time.
    pub fn lookup_one_with_policy<H>(&self, handle: H,
                                     keyflags: Option<KeyFlags>,
                                     or_by_primary: bool,
                                     policy: &dyn Policy,
                                     time: SystemTime)
        -> Result<Cert>
    where H: Into<FileStdinOrKeyHandle>
    {
        self.lookup_with_policy(std::iter::once(handle.into()),
                                keyflags, or_by_primary, false,
                                policy, time)
            .map(|certs| {
                assert_eq!(certs.len(), 1);
                certs.into_iter().next().expect("have one")
            })
    }


    /// Looks up certificates by User ID or email address.
    ///
    /// This only returns certificates that can be authenticate for
    /// the specified User ID (or email address, if `email` is true).
    /// If no certificate can be authenticated for some User ID,
    /// returns an error.  If multiple certificates can be
    /// authenticated for a given User ID or email address, then
    /// returns them all.
    pub fn lookup_by_userid(&self, userid: &[String], email: bool)
        -> Result<Vec<Cert>>
    {
        if userid.is_empty() {
            return Ok(Vec::new())
        }

        let cert_store = self.cert_store_or_else()?;

        // Build a WoT network.

        let cert_store = wot::store::CertStore::from_store(
            cert_store, self.policy, self.time);
        let n = wot::NetworkBuilder::rooted(&cert_store, &*self.trust_roots())
            .build();

        let mut results: Vec<Cert> = Vec::new();
        // We try hard to not just stop at the first error, but lint
        // the input so that the user gets as much feedback as
        // possible.  The first error that we encounter is saved here,
        // and returned.  The rest are printed directly.
        let mut error: Option<anyhow::Error> = None;

        // Iterate over each User ID address, find any certificates
        // associated with the User ID, validate the certificates, and
        // finally authenticate them for the User ID.
        for userid in userid.iter() {
            let matches: Vec<(Fingerprint, UserID)> = if email {
                if let Err(err) = UserIDQueryParams::is_email(userid) {
                    weprintln!("{:?} is not a valid email address", userid);
                    if error.is_none() {
                        error = Some(err);
                    }

                    continue;
                }

                // Get all certificates that are associated with the email
                // address.
                cert_store.lookup_synopses_by_email(userid)
            } else {
                let userid = UserID::from(&userid[..]);
                cert_store.lookup_synopses_by_userid(userid.clone())
                    .into_iter()
                    .map(|fpr| (fpr, userid.clone()))
                    .collect()
            };

            if matches.is_empty() {
                return Err(anyhow::anyhow!(
                    "No certificates are associated with {:?}",
                    userid));
            }

            struct Entry {
                fpr: Fingerprint,
                userid: UserID,
                cert: Result<Cert>,
            }
            let entries = matches.into_iter().map(|(fpr, userid)| {
                // We've got a match, or two, or three...  Lookup the certs.
                let cert = match cert_store.lookup_by_cert_fpr(&fpr) {
                    Ok(cert) => cert,
                    Err(err) => {
                        let err = err.context(format!(
                            "Error fetching {} ({})",
                            fpr, ui::Safe(&userid)));
                        return Entry { fpr, userid, cert: Err(err), };
                    }
                };

                // Parse the LazyCerts.
                let cert = match cert.to_cert() {
                    Ok(cert) => cert.clone(),
                    Err(err) => {
                        let err = err.context(format!(
                            "Error parsing {} ({})",
                            fpr, ui::Safe(&userid)));
                        return Entry { fpr, userid, cert: Err(err), };
                    }
                };

                // Check the certs for validity.
                let vc = match cert.with_policy(self.policy, self.time) {
                    Ok(vc) => vc,
                    Err(err) => {
                        let err = err.context(format!(
                            "Certificate {} ({}) is invalid",
                            fpr, ui::Safe(&userid)));
                        return Entry { fpr, userid, cert: Err(err) };
                    }
                };

                if let Err(err) = vc.alive() {
                    let err = err.context(format!(
                        "Certificate {} ({}) is invalid",
                        fpr, ui::Safe(&userid)));
                    return Entry { fpr, userid, cert: Err(err), };
                }

                if let RevocationStatus::Revoked(_) = vc.revocation_status() {
                    let err = anyhow::anyhow!(
                        "Certificate {} ({}) is revoked",
                        fpr, ui::Safe(&userid));
                    return Entry { fpr, userid, cert: Err(err), };
                }

                if let Some(ua) = vc.userids().find(|ua| {
                    ua.userid() == &userid
                })
                {
                    if let RevocationStatus::Revoked(_) = ua.revocation_status() {
                        let err = anyhow::anyhow!(
                            "User ID {} on certificate {} is revoked",
                            ui::Safe(&userid), fpr);
                        return Entry { fpr, userid, cert: Err(err), };
                    }
                }

                // Authenticate the bindings.
                let paths = n.authenticate(
                    &userid, cert.fingerprint(),
                    // XXX: Make this user configurable.
                    wot::FULLY_TRUSTED);
                let r = if paths.amount() < wot::FULLY_TRUSTED {
                    Err(anyhow::anyhow!(
                        "{}, {} cannot be authenticated at the \
                         required level ({} of {}).  After checking \
                         that {} really controls {}, you could certify \
                         their certificate by running \
                         `sq pki link add --cert {} --userid {:?}`.",
                        cert.fingerprint(),
                        ui::Safe(&userid),
                        paths.amount(), wot::FULLY_TRUSTED,
                        ui::Safe(&userid),
                        cert.fingerprint(),
                        cert.fingerprint(),
                        String::from_utf8_lossy(userid.value())))
                } else {
                    Ok(cert)
                };

                Entry { fpr, userid, cert: r, }
            });

            // Partition into good (successfully authenticated) and
            // bad (an error occurred).
            let (good, bad): (Vec<Entry>, _)
                = entries.partition(|entry| entry.cert.is_ok());

            if good.is_empty() {
                // We've only got errors.

                let err = if bad.is_empty() {
                    // We got nothing :/.
                    if email {
                        anyhow::anyhow!(
                            "No known certificates have the email address {}",
                            ui::Safe(userid))
                    } else {
                        anyhow::anyhow!(
                            "No known certificates have the User ID {}",
                            ui::Safe(userid))
                    }
                } else {
                    if email {
                        anyhow::anyhow!(
                            "None of the certificates with the email \
                             address {} can be authenticated using \
                             the configured trust model",
                            ui::Safe(userid))
                    } else {
                        anyhow::anyhow!(
                            "None of the certificates with the User ID \
                             {} can be authenticated using \
                             the configured trust model",
                            ui::Safe(userid))
                    }
                };

                weprintln!("{:?}:\n", err);
                if error.is_none() {
                    error = Some(err);
                }

                // Print the errors.
                for (i, Entry { fpr, userid, cert }) in bad.into_iter().enumerate() {
                    weprintln!("{}. When considering {} ({}):",
                               i + 1, fpr,
                               ui::Safe(&userid));
                    let err = match cert {
                        Ok(_) => unreachable!(),
                        Err(err) => err,
                    };

                    print_error_chain(&err);
                }
            } else {
                // We have at least one authenticated certificate.
                // Silently ignore any errors.
                results.extend(
                    good.into_iter().filter_map(|Entry { cert, .. }| {
                        cert.ok()
                    }));
            }
        }

        if let Some(error) = error {
            Err(error)
        } else {
            Ok(results)
        }
    }

    /// Returns the local trust root, creating it if necessary.
    pub fn local_trust_root(&self) -> Result<Arc<LazyCert<'store>>> {
        self.certd_or_else()?.trust_root().map(|(cert, _created)| {
            cert
        })
    }

    /// Returns the trust roots, including the cert store's trust
    /// root, if any.
    pub fn trust_roots(&self) -> Vec<Fingerprint> {
        let trust_root_local = self.trust_root_local.get_or_init(|| {
            self.cert_store_or_else()
                .ok()
                .and_then(|cert_store| cert_store.certd())
                .and_then(|certd| {
                    match certd.certd().get(cert_store::store::openpgp_cert_d::TRUST_ROOT) {
                        Ok(Some((_tag, cert_bytes))) => Some(cert_bytes),
                        // Not found.
                        Ok(None) => None,
                        Err(err) => {
                            weprintln!("Error looking up local trust root: {}",
                                       err);
                            None
                        }
                    }
                })
                .and_then(|cert_bytes| {
                    match RawCertParser::from_bytes(&cert_bytes[..]) {
                        Ok(mut parser) => {
                            match parser.next() {
                                Some(Ok(cert)) => Some(cert.fingerprint()),
                                Some(Err(err)) => {
                                    weprintln!("Local trust root is \
                                                corrupted: {}",
                                               err);
                                    None
                                }
                                None =>  {
                                    weprintln!("Local trust root is \
                                                corrupted: no data");
                                    None
                                }
                            }
                        }
                        Err(err) => {
                            weprintln!("Error parsing local trust root: {}",
                                       err);
                            None
                        }
                    }
                })
        });

        if let Some(trust_root_local) = trust_root_local {
            self.trust_roots.iter().cloned()
                .chain(std::iter::once(trust_root_local.clone()))
                .collect()
        } else {
            self.trust_roots.clone()
        }
    }

    /// Imports the TSK into the soft key backend.
    ///
    /// On success, returns whether the key was imported, updated, or
    /// unchanged and whether the cert was imported, updated, or
    /// unchanged.
    pub fn import_key(&self, cert: Cert, stats: &mut ImportStats)
                      -> Result<(ImportStatus, ImportStatus)>
    {
        if ! cert.is_tsk() {
            return Err(anyhow::anyhow!(
                "Nothing to import: certificate does not contain \
                 any secret key material"));
        }

        let keystore = self.key_store_or_else()?;
        let mut keystore = keystore.lock().unwrap();

        let mut softkeys = None;
        for mut backend in keystore.backends()?.into_iter() {
            if backend.id()? == "softkeys" {
                softkeys = Some(backend);
                break;
            }
        }

        drop(keystore);

        let mut softkeys = if let Some(softkeys) = softkeys {
            softkeys
        } else {
            return Err(anyhow::anyhow!("softkeys backend is not configured."));
        };

        let mut key_import_status = ImportStatus::Unchanged;
        for (s, key) in softkeys.import(&cert)
            .map_err(|e| {
                stats.keys.errors += 1;
                e
            })?
        {
            self.info(format_args!(
                "Importing {} into key store: {:?}",
                key.fingerprint(), s));

            key_import_status = key_import_status.max(s.into());
        }

        match key_import_status {
            ImportStatus::New => stats.keys.new += 1,
            ImportStatus::Unchanged => stats.keys.unchanged += 1,
            ImportStatus::Updated => stats.keys.updated += 1,
        }

        // Also insert the certificate into the certificate store.
        // If we can't, we don't fail.  This allows, in
        // particular, `sq --cert-store=none key import` to work.
        let cert = cert.strip_secret_key_material();
        let fpr = cert.fingerprint();
        let mut cert_import_status = ImportStatus::Unchanged;
        match self.cert_store_or_else() {
            Ok(cert_store) => {
                let new_certs = stats.certs.new_certs();
                let updated_certs = stats.certs.updated_certs();

                if let Err(err) = cert_store.update_by(
                    Arc::new(LazyCert::from(cert)), stats)
                {
                    self.info(format_args!(
                        "While importing {} into cert store: {}",
                        fpr, err));
                }

                if stats.certs.new_certs() > new_certs {
                    cert_import_status = ImportStatus::New;
                } else if stats.certs.updated_certs() > updated_certs {
                    cert_import_status = ImportStatus::Updated;
                }
            }
            Err(err) => {
                self.info(format_args!(
                    "Not importing {} into cert store: {}",
                    fpr, err));
            }
        }

        Ok((key_import_status, cert_import_status))
    }

    /// Imports the certificate into the certificate store.
    ///
    /// On success, returns whether the key was imported, updated, or
    /// unchanged.
    pub fn import_cert(&self, cert: Cert) -> Result<ImportStatus> {
        let fpr = cert.fingerprint();
        let cert_store = self.cert_store_or_else()?;

        let stats = MergePublicCollectStats::new();
        cert_store.update_by(Arc::new(LazyCert::from(cert)), &stats)
            .with_context(|| {
                format!("Failed to import {} into the certificate store",
                        fpr)
            })?;

        let import_status = if stats.new_certs() > 0 {
            ImportStatus::New
        } else if stats.updated_certs() > 0 {
            ImportStatus::Updated
        } else {
            ImportStatus::Unchanged
        };

        Ok(import_status)
    }

    /// Best-effort heuristic to compute the primary User ID of a given cert.
    ///
    /// The returned string is already sanitized, and safe for displaying.
    ///
    /// If `use_wot` is set, then we use the best authenticated user
    /// ID.  If `use_wot` is not set, then we use the primary user ID.
    pub fn best_userid<'u>(&self, cert: &'u Cert, use_wot: bool)
        -> PreferredUserID
    {
        // Try to be more helpful by including a User ID in the
        // listing.  We'd like it to be the primary one.  Use
        // decreasingly strict policies.
        let mut primary_uid = None;

        // First, apply our policy.
        if let Ok(vcert) = cert.with_policy(self.policy, self.time) {
            if let Ok(primary) = vcert.primary_userid() {
                primary_uid = Some(primary.userid());
            }
        }

        // Second, apply the null policy.
        if primary_uid.is_none() {
            if let Ok(vcert) = cert.with_policy(&NULL_POLICY, self.time) {
                if let Ok(primary) = vcert.primary_userid() {
                    primary_uid = Some(primary.userid());
                }
            }
        }

        // As a last resort, pick the first user id.
        if primary_uid.is_none() {
            if let Some(primary) = cert.userids().next() {
                primary_uid = Some(primary.userid());
            }
        }

        if let Some(primary_uid) = primary_uid {
            let fpr = cert.fingerprint();

            let mut candidate: (&UserID, usize) = (primary_uid, 0);

            #[allow(clippy::never_loop)]
            loop {
                // Don't fail if we can't query the user's web of trust.
                if ! use_wot { break; };
                let Ok(q) = self.wot_query() else { break; };
                let q = q.build();
                let authenticate = move |userid: &UserID| {
                    let paths = q.authenticate(userid, &fpr, wot::FULLY_TRUSTED);
                    paths.amount()
                };

                // We're careful to *not* use a ValidCert so that we see all
                // user IDs, even those that are not self signed.

                candidate = (primary_uid, authenticate(primary_uid));

                for userid in cert.userids() {
                    let userid = userid.component();

                    if candidate.1 >= wot::FULLY_TRUSTED {
                        // Done.
                        break;
                    }

                    if userid == primary_uid {
                        // We already considered this one.
                        continue;
                    }

                    let amount = authenticate(&userid);
                    if amount > candidate.1 {
                        candidate = (userid, amount);
                    }
                }

                break;
            }

            let (uid, amount) = candidate;
            PreferredUserID::from_userid(uid.clone(), amount)
        } else {
            // Special case, there is no user id.
            PreferredUserID::unknown()
        }
    }

    /// Best-effort heuristic to compute the primary User ID of a given cert.
    ///
    /// The returned string is already sanitized, and safe for displaying.
    ///
    /// If `use_wot` is set, then we use the best authenticated user
    /// ID.  If `use_wot` is not set, then we use the primary user ID.
    pub fn best_userid_for<'u, F>(&self,
                                  key_handle: &KeyHandle,
                                  keyflags: F,
                                  use_wot: bool)
                                  -> (PreferredUserID, Result<Cert>)
    where
        F: Into<Option<KeyFlags>>,
    {
        let certs = self.lookup(std::iter::once(key_handle),
                                keyflags.into(), false, true);

        match certs {
            Ok(certs) => {
                assert!(! certs.is_empty());

                // Compute the best user ID and the associated trust
                // amount for each cert.
                let mut certs = certs.into_iter().map(|c| {
                    (self.best_userid(&c, use_wot), c)
                }).collect::<Vec<_>>();

                // Sort by trust amount, then fingerprint.  This way,
                // if two certs have the same trust amount, at least
                // the result will be stable.
                certs.sort_by_key(
                    |(puid, cert)| (puid.trust_amount(), cert.fingerprint()));

                // Then pick the one with the highest trust amount.
                let best =
                    certs.into_iter().rev().next().expect("at least one");
                (best.0, Ok(best.1))
            }
            Err(err) => {
                if let Some(StoreError::NotFound(_))
                    = err.downcast_ref()
                {
                    (PreferredUserID::from_string("(certificate not found)", 0),
                     Err(err))
                } else {
                    (PreferredUserID::from_string(
                        format!("(error looking up certificate: {})", err), 0),
                     Err(err))
                }
            }
        }
    }

    /// Caches a password.
    pub fn cache_password(&self, password: Password) {
        let mut cache = self.password_cache.lock().unwrap();

        if ! cache.contains(&password) {
            cache.push(password);
        }
    }

    /// Returns the cached passwords.
    pub fn cached_passwords(&self) -> impl Iterator<Item=Password> {
        self.password_cache.lock().unwrap().clone().into_iter()
    }

    /// Decrypts a key, if possible.
    ///
    /// If the key is not decrypted, this just returns the key as is.
    /// Otherwise, the password cache is tried.  If the key can't be
    /// decrypted using those passwords and `may_prompt` is true, the
    /// user is prompted.  If a valid password is entered, it is added
    /// to the password cache.
    ///
    /// If `allow_skipping` is true, then the user is given the option
    /// to skip decrypting the key.  If the user skips decrypting the
    /// key, then an error is returned.
    pub fn decrypt_key<R>(&self, cert: Option<&Cert>,
                          key: Key<key::SecretParts, R>,
                          may_prompt: bool,
                          allow_skipping: bool)
        -> Result<Key<key::SecretParts, R>>
    where R: key::KeyRole + Clone
    {
        match key.secret() {
            SecretKeyMaterial::Unencrypted(_) => {
                Ok(key)
            }
            SecretKeyMaterial::Encrypted(e) => {
                if ! e.s2k().is_supported() {
                    return Err(anyhow::anyhow!(
                        "Unsupported key protection mechanism"));
                }

                for p in self.password_cache.lock().unwrap().iter() {
                    if let Ok(unencrypted) = e.decrypt(&key, &p) {
                        let (key, _) = key.add_secret(unencrypted.into());
                        return Ok(key);
                    }
                }

                let prompt = if let Some(cert) = cert {
                    format!("{}/{} {}",
                            cert.keyid(), key.keyid(),
                            self.best_userid(cert, true).display())
                } else {
                    format!("{}", key.keyid())
                };

                if ! may_prompt {
                    return Err(anyhow::anyhow!(
                        "Unable to decrypt secret key material for {}", prompt))
                }

                loop {
                    // Prompt the user.
                    let result = if allow_skipping {
                        password::prompt_to_unlock_or_cancel(self, &prompt)
                    } else {
                        password::prompt_to_unlock(self, &prompt).map(Some)
                    };
                    match result {
                        Ok(None) => break, // Give up.
                        Ok(Some(p)) => {
                            if let Ok(unencrypted) = e.decrypt(&key, &p) {
                                let (key, _) = key.add_secret(unencrypted.into());
                                self.password_cache.lock().unwrap().push(p);
                                return Ok(key);
                            }

                            weprintln!("Incorrect password.");
                        }
                        Err(err) => {
                            weprintln!("While reading password: {}", err);
                            break;
                        }
                    }
                }

                Err(anyhow::anyhow!("Key {}: Unable to decrypt secret key material",
                                    key.keyid().to_hex()))
            }
        }
    }

    /// Checks whether we have a secret key.
    pub fn have_secret_key<P, R, R2>(&self, ka: &KeyAmalgamation<P, R, R2>)
                                     -> bool
    where
        P: key::KeyParts + Clone,
        R: key::KeyRole + Clone
    {
        let try_tsk = |_: &Cert, key: &Key<_, _>|
            -> Result<_>
        {
            key.parts_as_secret()?;
            Ok(())
        };
        let try_keyrings = |cert: &Cert, key: &Key<_, _>|
            -> Result<_>
        {
            let keyring_tsks = self.keyring_tsks()?;
            if let Some((cert_fpr, key))
                = keyring_tsks.get(&key.fingerprint())
            {
                if cert_fpr == &cert.fingerprint() {
                    return try_tsk(cert, key);
                }
            }

            Err(anyhow!("no secret key material"))
        };
        let try_keystore = |ka: &KeyAmalgamation<_, _, R2>|
            -> Result<_>
        {
            let ks = self.key_store_or_else()?;
            let mut ks = ks.lock().unwrap();
            if ks.find_key(ka.key().key_handle())?.is_empty() {
                Err(anyhow!("no secret key material in the store"))
            } else {
                Ok(())
            }
        };

        let key = ka.key().parts_as_public().role_as_unspecified();
        try_tsk(ka.cert(), key)
            .or_else(|_| try_keyrings(ka.cert(), key))
            .or_else(|_| try_keystore(ka))
            .is_ok()
    }

    /// Gets a signer for the specified key.
    ///
    /// If `ka` includes secret key material, that is preferred.
    /// Otherwise, we look for the key on the key store.
    ///
    /// If the key is locked, we try to unlock it.  If the key isn't
    /// protected by a retry counter, then the password cache is
    /// tried.  Otherwise, or if that fails, the user is prompted to
    /// unlock the key.  The correct password is added to the password
    /// cache.
    pub fn get_signer<P, R, R2>(&self, ka: &KeyAmalgamation<P, R, R2>)
        -> Result<Box<dyn crypto::Signer + Send + Sync>>
        where P: key::KeyParts + Clone, R: key::KeyRole + Clone
    {
        let try_tsk = |cert: &Cert, key: &Key<_, _>|
            -> Result<_>
        {
            if let Ok(key) = key.parts_as_secret() {
                let key = self.decrypt_key(
                    Some(cert), key.clone(), true, false)?;
                let keypair = Box::new(key.into_keypair()
                    .expect("decrypted secret key material"));
                Ok(keypair)
            } else {
                Err(anyhow!("No secret key material."))
            }
        };
        let try_keyrings = |cert: &Cert, key: &Key<_, _>|
            -> Result<_>
        {
            let keyring_tsks = self.keyring_tsks()?;
            if let Some((cert_fpr, key))
                = keyring_tsks.get(&key.fingerprint())
            {
                if cert_fpr == &cert.fingerprint() {
                    return try_tsk(cert, key);
                }
            }

            Err(anyhow!("No secret key material."))
        };
        let try_keystore = |ka: &KeyAmalgamation<_, _, R2>|
            -> Result<_>
        {
            let ks = self.key_store_or_else()?;

            let mut ks = ks.lock().unwrap();

            let remote_keys = ks.find_key(ka.key().key_handle())?;

            let uid = self.best_userid(ka.cert(), true);

            // XXX: Be a bit smarter.  If there are multiple
            // keys, sort them so that we try the easiest one
            // first (available, no password).

            'key: for mut key in remote_keys.into_iter() {
                if let Protection::Password(hint) = key.locked()? {
                    if self.cached_passwords()
                        .find(|password| {
                            key.unlock(password.clone()).is_ok()
                        })
                        .is_none()
                    {
                        if let Some(hint) = hint {
                            weprintln!("{}", hint);
                        }

                        loop {
                            let p = password::prompt_to_unlock(self, &format!(
                                "{}/{}, {}",
                                ka.cert().keyid(), ka.key().keyid(),
                                uid.display()))?;

                            if p == "".into() {
                                weprintln!("Giving up.");
                                continue 'key;
                            }

                            match key.unlock(p.clone()) {
                                Ok(()) => {
                                    self.cache_password(p.clone());
                                    break;
                                }
                                Err(err) => {
                                    weprintln!("Failed to unlock key: {}", err);
                                }
                            }
                        }
                    }
                }

                return Ok(Box::new(key));
            }

            Err(anyhow!("Key not managed by keystore."))
        };

        let key = ka.key().parts_as_public().role_as_unspecified();

        if let Ok(key) = try_tsk(ka.cert(), key) {
            Ok(key)
        } else if let Ok(key) = try_keyrings(ka.cert(), key) {
            Ok(key)
        } else if let Ok(key) = try_keystore(ka) {
            Ok(key)
        } else {
            Err(anyhow!("No secret key material."))
        }
    }

    /// Returns a signer for each certificate.
    ///
    /// This returns one key for each certificate.  If a certificate
    /// doesn't have a suitable key, then this returns an error.
    ///
    /// A key is considered suitable if:
    ///
    /// - the certificate is valid
    /// - the key matches the key type specified in `keytype` (it's either
    ///   the primary, or it has one of the key capabilities)
    /// - the key is alive (unless allowed by `options`)
    /// - the key is not revoked (unless allowed by `options`)
    /// - the key's algorithm is supported by the underlying crypto engine.
    ///
    /// If a key is locked, then the user will be prompted to enter
    /// the password.
    fn get_keys<C>(&self, certs: &[C],
                   keytype: KeyType,
                   options: Option<&[GetKeysOptions]>)
        -> Result<Vec<(Cert, Box<dyn crypto::Signer + Send + Sync>)>>
    where C: Borrow<Cert>
    {
        let mut bad = Vec::new();

        let options = options.unwrap_or(&[][..]);
        let allow_not_alive = options.contains(&GetKeysOptions::AllowNotAlive);
        let allow_revoked = options.contains(&GetKeysOptions::AllowRevoked);
        let null_policy = options.contains(&GetKeysOptions::NullPolicy);

        let policy = if null_policy {
            &NULL_POLICY as &dyn Policy
        } else {
            self.policy as &dyn Policy
        };

        let mut keys = vec![];

        'next_cert: for cert in certs {
            let cert = cert.borrow();
            let vc = match cert.with_policy(policy, self.time) {
                Ok(vc) => vc,
                Err(err) => {
                    return Err(
                        err.context(format!("Found no suitable key on {}", cert)));
                }
            };

            let keyiter = match keytype {
                KeyType::Primary => {
                    Box::new(
                        std::iter::once(
                            vc.keys()
                                .next()
                                .expect("a valid cert has a primary key")))
                        as Box<dyn Iterator<Item=ValidErasedKeyAmalgamation<openpgp::packet::key::PublicParts>>>
                },
                KeyType::KeyFlags(ref flags) => {
                    Box::new(vc.keys().key_flags(flags.clone()))
                        as Box<dyn Iterator<Item=_>>
                },
            };
            for ka in keyiter {
                let mut bad_ = [
                    ! allow_not_alive && matches!(ka.alive(), Err(_)),
                    ! allow_revoked && matches!(ka.revocation_status(),
                                                RevocationStatus::Revoked(_)),
                    ! ka.key().pk_algo().is_supported(),
                    false,
                ];
                if bad_.iter().any(|x| *x) {
                    bad.push((ka.key().fingerprint(), bad_));
                    continue;
                }

                if let Ok(key) = self.get_signer(ka.amalgamation()) {
                    keys.push((cert.clone(), key));
                    continue 'next_cert;
                } else {
                    bad_[3] = true;
                    bad.push((ka.key().fingerprint(), bad_));
                    continue;
                }
            }

            // We didn't get a key.  Lint the cert.

            let time = chrono::DateTime::<chrono::offset::Utc>::from(self.time);

            let mut context = Vec::new();
            for (fpr, [not_alive, revoked, not_supported, no_secret_key]) in bad {
                let id: String = if fpr == cert.fingerprint() {
                    fpr.to_string()
                } else {
                    format!("{}/{}", cert.fingerprint(), fpr)
                };

                let preface = if ! self.time_is_now {
                    format!("{} was not considered because\n\
                             at the specified time ({}) it was",
                            id, time)
                } else {
                    format!("{} was not considered because\nit is", fpr)
                };

                let mut reasons = Vec::new();
                if not_alive {
                    reasons.push("not alive");
                }
                if revoked {
                    reasons.push("revoked");
                }
                if not_supported {
                    reasons.push("not supported");
                }
                if no_secret_key {
                    reasons.push("missing the secret key");
                }

                context.push(format!("{}: {}",
                                     preface, reasons.join(", ")));
            }

            if context.is_empty() {
                return Err(anyhow::anyhow!(
                    format!("Found no suitable key on {}", cert)));
            } else {
                let context = context.join("\n");
                return Err(
                    anyhow::anyhow!(
                        format!("Found no suitable key on {}", cert))
                        .context(context));
            }
        }

        Ok(keys)
    }

    /// Returns a signer for each certificate's primary key.
    ///
    /// This returns one key for each certificate.  If a certificate
    /// doesn't have a suitable key, then this returns an error.
    ///
    /// A key is considered suitable if:
    ///
    /// - the certificate is valid
    /// - the key is alive (unless allowed by `options`)
    /// - the key is not revoked (unless allowed by `options`)
    /// - the key's algorithm is supported by the underlying crypto engine.
    ///
    /// If a key is locked, then the user will be prompted to enter
    /// the password.
    pub fn get_primary_keys<C>(&self, certs: &[C],
                               options: Option<&[GetKeysOptions]>)
        -> Result<Vec<Box<dyn crypto::Signer + Send + Sync>>>
    where C: std::borrow::Borrow<Cert>
    {
        self.get_keys(certs, KeyType::Primary, options)
            .map(|keys| keys.into_iter()
                 .map(|(_, signer)| signer)
                 .collect())
    }

    /// Returns a signer for the certificate's primary key.
    ///
    /// If the certificate doesn't have a suitable key, then this
    /// returns an error.
    ///
    /// A key is considered suitable if:
    ///
    /// - the certificate is valid
    /// - the key is alive (unless allowed by `options`)
    /// - the key is not revoked (unless allowed by `options`)
    /// - the key's algorithm is supported by the underlying crypto engine.
    ///
    /// If a key is locked, then the user will be prompted to enter
    /// the password.
    pub fn get_primary_key<C>(&self, certs: C,
                              options: Option<&[GetKeysOptions]>)
        -> Result<Box<dyn crypto::Signer + Send + Sync>>
    where C: std::borrow::Borrow<Cert>
    {
        let keys = self.get_primary_keys(&[certs], options)?;
        assert!(
            keys.len() == 1,
            "Expected exactly one result from get_primary_keys()"
        );
        Ok(keys.into_iter().next().unwrap())
    }

    /// Returns a signer for a signing-capable key for each
    /// certificate.
    ///
    /// This returns one key for each certificate.  If a certificate
    /// doesn't have a suitable key, then this returns an error.
    ///
    /// A key is considered suitable if:
    ///
    /// - the certificate is valid
    /// - the key is signing capable
    /// - the key is alive (unless allowed by `options`)
    /// - the key is not revoked (unless allowed by `options`)
    /// - the key's algorithm is supported by the underlying crypto engine.
    ///
    /// If a key is locked, then the user will be prompted to enter
    /// the password.
    pub fn get_signing_keys<C>(&self, certs: &[C],
                               options: Option<&[GetKeysOptions]>)
        -> Result<Vec<(Cert, Box<dyn crypto::Signer + Send + Sync>)>>
    where C: Borrow<Cert>
    {
        self.get_keys(certs,
                      KeyType::KeyFlags(KeyFlags::empty().set_signing()),
                      options)
    }

    /// Returns a signer for a signing-capable key for the
    /// certificate.
    ///
    /// If a certificate doesn't have a suitable key, then this
    /// returns an error.
    ///
    /// A key is considered suitable if:
    ///
    /// - the certificate is valid
    /// - the key is signing capable
    /// - the key is alive (unless allowed by `options`)
    /// - the key is not revoked (unless allowed by `options`)
    /// - the key's algorithm is supported by the underlying crypto engine.
    ///
    /// If a key is locked, then the user will be prompted to enter
    /// the password.
    pub fn get_signing_key<C>(&self, cert: C,
                               options: Option<&[GetKeysOptions]>)
        -> Result<Box<dyn crypto::Signer + Send + Sync>>
    where C: Borrow<Cert>
    {
        let keys = self.get_signing_keys(&[cert], options)?;
        assert!(
            keys.len() == 1,
            "Expected exactly one result from get_signing_keys()"
        );
        Ok(keys.into_iter().next().unwrap().1)
    }

    /// Returns a signer for a certification-capable key for each
    /// certificate.
    ///
    /// This returns one key for each certificate.  If a certificate
    /// doesn't have a suitable key, then this returns an error.
    ///
    /// A key is considered suitable if:
    ///
    /// - the certificate is valid
    /// - the key is certification capable
    /// - the key is alive (unless allowed by `options`)
    /// - the key is not revoked (unless allowed by `options`)
    /// - the key's algorithm is supported by the underlying crypto engine.
    ///
    /// If a key is locked, then the user will be prompted to enter
    /// the password.
    pub fn get_certification_keys<C>(&self, certs: &[C],
                                     options: Option<&[GetKeysOptions]>)
        -> Result<Vec<(Cert, Box<dyn crypto::Signer + Send + Sync>)>>
    where C: std::borrow::Borrow<Cert>
    {
        self.get_keys(certs,
                      KeyType::KeyFlags(KeyFlags::empty().set_certification()),
                      options)
    }

    /// Returns a signer for a certification-capable key for the
    /// certificate.
    ///
    /// This returns one key for each certificate.  If a certificate
    /// doesn't have a suitable key, then this returns an error.
    ///
    /// A key is considered suitable if:
    ///
    /// - the certificate is valid
    /// - the key is certification capable
    /// - the key is alive (unless allowed by `options`)
    /// - the key is not revoked (unless allowed by `options`)
    /// - the key's algorithm is supported by the underlying crypto engine.
    ///
    /// If a key is locked, then the user will be prompted to enter
    /// the password.
    pub fn get_certification_key<C>(&self, cert: C,
                                    options: Option<&[GetKeysOptions]>)
        -> Result<Box<dyn crypto::Signer + Send + Sync>>
    where C: std::borrow::Borrow<Cert>
    {
        let keys = self.get_certification_keys(&[cert], options)?;
        assert!(
            keys.len() == 1,
            "Expected exactly one result from get_certification_keys()"
        );
        Ok(keys.into_iter().next().unwrap().1)
    }

    /// Prints additional information in verbose mode.
    pub fn info(&self, msg: fmt::Arguments) {
        if self.verbose() {
            weprintln!("{}", msg);
        }
    }

    /// Prints a hint for the user.
    pub fn hint(&self, msg: fmt::Arguments) -> Hint {
        Hint::new(! self.config.hints())
            .hint(msg)
    }

    /// Resolve cert designators to certificates.
    ///
    /// When matching on a user ID, a certificate is only returned if
    /// the matching user ID can be authenticated at the specified
    /// amount (`trust_amount`).  Note: when `trust_amount` is 0,
    /// matching user IDs do not have to be self signed.  If a
    /// designator matches multiple certificates, all of them are
    /// returned.
    ///
    /// When matching by key handle via `--cert`, or reading a
    /// certificate from a file, or from stdin, the certificate is not
    /// further authenticated.
    ///
    /// The returned certificates are deduped (duplicate certificates
    /// are merged).
    ///
    /// This function returns a vector of certificates and a vector of
    /// errors.  If processing a certificate results in an error, we
    /// add it to the list of errors.  If a designator does not match
    /// any certificates, an error is added to the error vector.  In
    /// general, designator-specific errors are returned as `Err`s in
    /// the `Vec`.  General errors, like the certificate store is
    /// disabled, are returned using the outer `Result`.
    pub fn resolve_certs<Arguments, Prefix, Options, Doc>(
        &self,
        designators: &CertDesignators<Arguments, Prefix, Options, Doc>,
        trust_amount: TrustThreshold,
    )
        -> Result<(Vec<Cert>, Vec<anyhow::Error>)>
    where
        Prefix: cert_designator::ArgumentPrefix,
    {
        self.resolve_certs_filter(designators, trust_amount, &mut |_, _| Ok(()))
    }


    /// Like [`Sq::resolve_certs`], but takes a filter option.
    ///
    /// The filter is applied in such a way that cert designators that
    /// can match more than one certificate (such as `--cert-domain`)
    /// only fail if they don't match any cert after filtering.
    ///
    /// Note: just because `filter` is called on a certificate, and it
    /// returns `Ok` doesn't mean that the certificate will
    /// necessarily be returned.
    pub fn resolve_certs_filter<Arguments, Prefix, Options, Doc>(
        &self,
        designators: &CertDesignators<Arguments, Prefix, Options, Doc>,
        trust_amount: TrustThreshold,
        filter: &mut dyn FnMut(&cert_designator::CertDesignator, &LazyCert)
                               -> Result<()>,
    )
        -> Result<(Vec<Cert>, Vec<anyhow::Error>)>
    where
        Prefix: cert_designator::ArgumentPrefix,
    {
        self.resolve_certs_filter_intern(
            &designators.designators, Prefix::prefix(), trust_amount, filter)
    }

    /// Like [`Sq::resolve_certs_filter`], but prevents
    /// monomorphization.
    fn resolve_certs_filter_intern(
        &self,
        designators: &[cert_designator::CertDesignator],
        prefix: &str,
        trust_amount: TrustThreshold,
        mut filter: &mut dyn FnMut(&cert_designator::CertDesignator, &LazyCert)
                                   -> Result<()>,
    )
        -> Result<(Vec<Cert>, Vec<anyhow::Error>)>
    {
        tracer!(TRACE, "Sq::resolve_certs_filter_intern");
        t!("{:?}", designators);

        // To report all errors, and not just the first one that we
        // encounter, we maintain a list of errors.
        let mut errors: Vec<anyhow::Error> = Vec::new();

        // We merge the certificates eagerly.  To do so, we maintain a
        // list of certificates that we've looked up.
        let mut results: Vec<Cert> = Vec::new();

        // Whether `ret` added something.  This needs to be a
        // `RefCell`. because the `ret` closure holds a `&mut` to
        // `results`.
        let matched: RefCell<bool> = RefCell::new(false);

        // Whether we've seen the given certificate.  The boolean is
        // if we merged in the certificate from the cert store.  The
        // index is the index of the certificate in `results`.
        let mut have: BTreeMap<Fingerprint, (bool, usize)>
            = BTreeMap::new();

        // The list of user ID queries.
        let mut userid_queries: Vec<(&cert_designator::CertDesignator, _, String)>
            = Vec::new();

        // Only open the cert store if we actually need it.
        let mut cert_store_ = None;
        let mut cert_store = || -> Result<_> {
            if let Some(cert_store) = cert_store_ {
                Ok(cert_store)
            } else {
                cert_store_ = Some(self.cert_store_or_else()?);
                Ok(cert_store_.expect("just set"))
            }
        };

        // Return a certificate or an error to the caller.
        //
        // `from_cert_store` is whether the certificate was read from
        // the certificate store or not.
        //
        // If `apply_filter` is true, `filter` is applied.  This
        // should be done for designators that precisely designate
        // certs (e.g. by fingerprint, or file), and false if the designator can
        // match more than one cert (e.g. by user ID match).
        let mut ret = |designator: &cert_designator::CertDesignator,
                       cert: Result<Arc<LazyCert>>,
                       from_cert_store: bool,
                       apply_filter: Option<
                               &mut dyn FnMut(&cert_designator::CertDesignator,
                                              &LazyCert)
                                              -> Result<()>>|
        {
            let cert = match cert {
                Ok(cert) => cert,
                Err(err) => {
                    errors.push(
                        err.context(format!(
                            "Failed to resolve {}",
                            designator.argument_with_prefix(prefix))));
                    return;
                }
            };

            if let Some(filter) = apply_filter {
                if let Err(err) = filter(designator, &cert) {
                    errors.push(
                        err.context(format!(
                            "Failed to resolve {}",
                            designator.argument_with_prefix(prefix))));
                    return;
                }
            }

            match have.entry(cert.fingerprint()) {
                Entry::Occupied(mut oe) => {
                    let (have_from_cert_store, have_cert) = oe.get_mut();
                    if from_cert_store {
                        if *have_from_cert_store {
                            // We read `cert` from the cert store, and
                            // we read the same cert from the cert
                            // store in the past.  There's nothing to
                            // merge; we're done.
                            *matched.borrow_mut() = true;
                            return;
                        }
                    }

                    let cert = match cert.to_cert() {
                        Ok(cert) => cert.clone(),
                        Err(err) => {
                            errors.push(
                                err.context(format!(
                                    "Failed to resolve {}",
                                    designator.argument_with_prefix(prefix))));
                            return;
                        }
                    };

                    assert!(*have_cert < results.len());
                    if let Some(have_cert) = results.get_mut(*have_cert) {
                        *have_cert = have_cert.clone()
                            .merge_public_and_secret(cert)
                            .expect("same cert");
                    }

                    *have_from_cert_store |= from_cert_store;

                    *matched.borrow_mut() = true;
                }
                Entry::Vacant(ve) => {
                    let cert = match cert.to_cert() {
                        Ok(cert) => cert.clone(),
                        Err(err) => {
                            errors.push(
                                err.context(format!(
                                    "Failed to resolve {}",
                                    designator.argument_with_prefix(prefix))));
                            return;
                        }
                    };

                    ve.insert((from_cert_store, results.len()));

                    results.push(cert);

                    *matched.borrow_mut() = true;
                }
            }
        };

        for designator in designators {
            *matched.borrow_mut() = false;

            match designator {
                cert_designator::CertDesignator::Cert(kh) => {
                    t!("Looking up certificate by handle {}", kh);

                    match cert_store()?.lookup_by_cert(kh) {
                        Ok(matches) => {
                            for cert in matches.into_iter() {
                                // We matched on the primary key.
                                ret(designator, Ok(cert), true, Some(&mut filter));
                            }
                        }
                        Err(err) => {
                            ret(designator, Err(err), true, Some(&mut filter));
                        }
                    }
                }

                cert_designator::CertDesignator::UserID(userid) => {
                    t!("Looking up certificate by userid {:?}", userid);

                    match designator.query_params() {
                        Ok(Some((q, pattern))) =>
                            userid_queries.push((designator, q, pattern)),

                        Ok(None) =>
                            unreachable!("designator matches on user IDs"),

                        Err(err) =>
                            ret(designator, Err(err), true, None),
                    }
                }

                cert_designator::CertDesignator::Email(email) => {
                    t!("Looking up certificate by email {:?}", email);

                    match designator.query_params() {
                        Ok(Some((q, pattern))) =>
                            userid_queries.push((designator, q, pattern)),

                        Ok(None) =>
                            unreachable!("designator matches on user IDs"),

                        Err(err) =>
                            ret(designator, Err(err), true, None),
                    }
                }

                cert_designator::CertDesignator::Domain(domain) => {
                    t!("Looking up certificate by domain {:?}", domain);

                    match designator.query_params() {
                        Ok(Some((q, pattern))) =>
                            userid_queries.push((designator, q, pattern)),

                        Ok(None) =>
                            unreachable!("designator matches on user IDs"),

                        Err(err) =>
                            ret(designator, Err(err), true, None),
                    }
                }

                cert_designator::CertDesignator::Grep(pattern) => {
                    t!("Looking up certificate by pattern {:?}", pattern);

                    match designator.query_params() {
                        Ok(Some((q, pattern))) =>
                            userid_queries.push((designator, q, pattern)),

                        Ok(None) =>
                            unreachable!("designator matches on user IDs"),

                        Err(err) =>
                            ret(designator, Err(err), true, None),
                    }
                }

                cert_designator::CertDesignator::File(filename) => {
                    t!("Reading certificates from the file {}",
                       filename.display());

                    match crate::load_certs(
                        std::iter::once(filename.as_path()))
                    {
                        Ok(found) => {
                            if found.is_empty() {
                                ret(designator,
                                    Err(anyhow::anyhow!(
                                        "File does not contain any \
                                         certificates")),
                                    false, Some(&mut filter));
                            } else {
                                for cert in found.into_iter() {
                                    ret(designator,
                                        Ok(Arc::new(cert.into())),
                                        false, Some(&mut filter));
                                }
                            }
                        },
                        Err(err) => {
                            ret(designator, Err(err), false, Some(&mut filter));
                        }
                    }
                }

                cert_designator::CertDesignator::Stdin => {
                    t!("Reading certificates from stdin");
                    let parser = CertParser::from_reader(StdinWarning::certs())
                        .with_context(|| {
                            format!("Failed to load certs from stdin")
                        })?;
                    for cert in parser {
                        match cert {
                            Ok(cert) => {
                                ret(
                                    designator,
                                    Ok(Arc::new(cert.into())),
                                    false, Some(&mut filter));
                            }
                            Err(err) => {
                                ret(designator,
                                    Err(err),
                                    false, Some(&mut filter));
                                continue;
                            }
                        }
                    }
                    if ! *matched.borrow() {
                        ret(
                            designator,
                            Err(anyhow::anyhow!(
                                "stdin did not contain any certificates")),
                            false, Some(&mut filter));
                    }
                }
                cert_designator::CertDesignator::Special(name) => {
                    let certd = match self.certd_or_else() {
                        Ok(certd) => certd,
                        Err(err) => {
                            ret(
                                designator,
                                Err(err),
                                true, Some(&mut filter));
                            continue;
                        }
                    };

                    let result = match name {
                        SpecialName::PublicDirectories => {
                            certd.public_directory_ca()
                        }
                        SpecialName::KeysOpenpgpOrg => {
                            certd.shadow_ca_keys_openpgp_org()
                        }
                        SpecialName::KeysMailvelopeCom => {
                            certd.shadow_ca_keys_mailvelope_com()
                        }
                        SpecialName::ProtonMe => {
                            certd.shadow_ca_proton_me()
                        }
                        SpecialName::WKD => {
                            certd.shadow_ca_wkd()
                        }
                        SpecialName::DANE => {
                            certd.shadow_ca_dane()
                        }
                        SpecialName::Autocrypt => {
                            certd.shadow_ca_autocrypt()
                        }
                        SpecialName::Web => {
                            certd.shadow_ca_web()
                        }
                    };

                    ret(
                        designator,
                        result
                            .map(|(cert, _created)| cert)
                            .with_context(|| {
                                format!("Looking up special certificate {}",
                                        name)
                            }),
                        true, Some(&mut filter));
                },

                cert_designator::CertDesignator::Self_ => {
                    let (certs, config): (Box<dyn Iterator<Item=&Fingerprint>>, _)
                        = match prefix
                    {
                        "for-" => (
                            Box::new(self.config.encrypt_for_self().iter()),
                            cli::encrypt::ENCRYPT_FOR_SELF,
                        ),
                        "signer-" => (
                            Box::new(self.config.sign_signer_self().iter()),
                            cli::sign::SIGNER_SELF,
                        ),
                        "certifier-" => (
                            Box::new(self.config.pki_vouch_certifier_self().iter()),
                            cli::pki::vouch::CERTIFIER_SELF,
                        ),
                        _ => return Err(anyhow::anyhow!(
                            "self designator used with unexpected prefix: {}", prefix)),
                    };

                    let mut one = false;
                    for fp in certs {
                        let cert = self.resolve_cert(
                            &openpgp::KeyHandle::from(
                                fp.clone()).into(), TrustThreshold::YOLO)?.0;
                        ret(designator,
                            Ok(Arc::new(cert.into())),
                            true, Some(&mut filter));
                        one = true;
                    }

                    if ! one {
                        return Err(anyhow::anyhow!(
                            "`--{}self` is given but no default \
                             is set in the configuration file under `{}`",
                            prefix,
                            config));
                    }
                },
            }
        }

        let n = if ! userid_queries.is_empty() {
            Some(self.wot_query()?.build())
        } else {
            None
        };

        for (designator, q, pattern) in userid_queries.iter() {
            t!("Executing query {:?} against {}", q, pattern);

            let n = n.as_ref().unwrap();

            *matched.borrow_mut() = false;

            let cert_store = cert_store()?;
            match cert_store.select_userid(q, pattern) {
                Ok(found) => {
                    t!("=> {} results", found.len());

                    // Apply the filter, if any.
                    let (found, error) = found.into_iter().fold(
                        (Vec::new(), None),
                        |(mut found, mut error), c|
                        {
                            match filter(designator, &c) {
                                Ok(()) => found.push(c),
                                Err(err) => {
                                    if error.is_none() {
                                        error = Some(err);
                                    }
                                }
                            }

                            (found, error)
                        });

                    if found.is_empty() {
                        ret(designator,
                            Err(error.unwrap_or_else(|| {
                                anyhow::anyhow!(
                                    "query did not match any certificates")
                            })),
                            true, None);
                        continue;
                    }

                    // If the designator doesn't match anything, we
                    // can sometimes provide a hint, e.g., weak
                    // crypto.
                    let mut hint = Vec::new();

                    for cert in found.into_iter() {
                        let mut authenticated = false;
                        if trust_amount == TrustThreshold::YOLO {
                            authenticated = true;
                        } else {
                            // Find the matching user ID and
                            // authenticate it.
                            for userid in cert.userids() {
                                if q.check(&userid, pattern) {
                                    let paths = n.authenticate(
                                        &userid, cert.fingerprint(),
                                        trust_amount.into());
                                    if paths.amount() < trust_amount.into() {
                                        hint.push(Err(anyhow::anyhow!(
                                            "{}, {} cannot be authenticated \
                                             at the required level ({} of {}). \
                                             After checking that {} really \
                                             controls {}, you could certify \
                                             their certificate by running \
                                             `sq pki link add --cert {} \
                                             --userid {:?}`.",
                                            cert.fingerprint(),
                                            ui::Safe(&userid),
                                            paths.amount(), trust_amount,
                                            ui::Safe(&userid),
                                            cert.fingerprint(),
                                            cert.fingerprint(),
                                            String::from_utf8_lossy(userid.value()))));
                                    } else {
                                        authenticated = true;
                                        break;
                                    }
                                }
                            }
                        }

                        if authenticated {
                            ret(designator, Ok(cert), true, None);
                        }
                    }

                    if ! *matched.borrow() {
                        // The designator didn't match any
                        // certificates.
                        if hint.is_empty() {
                            ret(designator,
                                Err(anyhow::anyhow!("Didn't match any certificates")),
                                true, None);
                        } else {
                            for hint in hint.into_iter() {
                                ret(designator,
                                    hint,
                                    true, None);
                            }
                        }
                    }
                }
                Err(err) => {
                    t!("=> {}", err);
                    ret(designator, Err(err), true, None);
                }
            }
        }

        Ok((results, errors))
    }

    /// Like `Sq::resolve_certs`, but bails if there is an error
    /// resolving a certificate.
    pub fn resolve_certs_or_fail<Arguments, Prefix, Options, Doc>(
        &self,
        designators: &CertDesignators<Arguments, Prefix, Options, Doc>,
        trust_amount: TrustThreshold,
    )
        -> Result<Vec<Cert>>
    where
        Prefix: cert_designator::ArgumentPrefix,
    {
        let (certs, errors) = self.resolve_certs(designators, trust_amount)?;

        for error in errors.iter() {
            print_error_chain(error);
        }
        if ! errors.is_empty() {
            return Err(anyhow::anyhow!("Failed to resolve certificates"));
        }

        Ok(certs)
    }

    /// Like `Sq::resolve_certs`, but bails if there is not exactly
    /// one designator, or the designator resolves to multiple
    /// certificates.
    ///
    /// Returns whether the certificate was read from a file.
    pub fn resolve_cert<Arguments, Prefix, Options, Doc>(
        &self,
        designators: &CertDesignators<Arguments, Prefix, Options, Doc>,
        trust_amount: TrustThreshold,
    )
        -> Result<(Cert, FileStdinOrKeyHandle)>
    where
        Prefix: cert_designator::ArgumentPrefix,
    {
        self.resolve_cert_intern(
            &designators.designators, Prefix::prefix(), trust_amount)
    }

    /// Like [`Sq::resolve_certs`], but prevents monomorphization.
    fn resolve_cert_intern(
        &self,
        designators: &[cert_designator::CertDesignator],
        prefix: &str,
        trust_amount: TrustThreshold,
    )
        -> Result<(Cert, FileStdinOrKeyHandle)>
    {
        // Assuming this is only called with OneValue, then the
        // following are not required.
        if designators.len() == 0 {
            panic!("clap failed to enforce that the {} argument is \
                    required.",
                   prefix);
        } else if designators.len() > 1 {
            panic!("clap failed to enforce that the {} argument is \
                    specified at most once.",
                   prefix);
        }

        let (certs, errors) =
            self.resolve_certs_filter_intern(designators, prefix, trust_amount,
                                             &mut |_, _| Ok(()))?;
        if certs.len() > 1 {
            weprintln!("{} is ambiguous.  It resolves to multiple certificates.",
                       designators[0].argument_with_prefix(prefix));
            for cert in certs.iter() {
                eprintln!("  - {} {}",
                          cert.fingerprint(),
                          self.best_userid(cert, true).display());
            }

            return Err(anyhow::anyhow!(
                "{} is ambiguous.  It resolves to multiple certificates.",
                designators[0].argument_with_prefix(prefix)))
        }

        if let Some(errors) = errors.into_iter().next() {
            return Err(errors);
        }

        let cert = certs.into_iter().next().unwrap();
        let handle = cert.key_handle();
        Ok((cert,
            match &designators[0] {
                cert_designator::CertDesignator::Stdin =>
                    FileStdinOrKeyHandle::FileOrStdin(Default::default()),
                cert_designator::CertDesignator::File(p) =>
                    FileStdinOrKeyHandle::FileOrStdin(p.as_path().into()),
                _ => handle.into()
            }))
    }

    /// Resolves keys.
    ///
    /// Keys are resolved to valid keys (according to the current
    /// policy) that are not hard revoked.
    ///
    /// `cert` and `cert_handle` are as returned by
    /// `sq::resolve_cert`.
    pub fn resolve_keys<'a, KOptions, KDoc>(
        &self,
        vc: &ValidCert<'a>, cert_handle: &FileStdinOrKeyHandle,
        keys: &KeyDesignators<KOptions, KDoc>,
        return_hard_revoked: bool)
        -> Result<Vec<ValidErasedKeyAmalgamation<'a, PublicParts>>>
    where
        KOptions: typenum::Unsigned,
    {
        assert!(keys.len() > 0);

        let options = KOptions::to_usize();
        let only_subkeys = (options & key_designator::OnlySubkeys::to_usize()) > 0;

        let khs = keys.iter()
            .map(|d| {
                match d {
                    key_designator::KeyDesignator::KeyHandle(kh) => kh,
                }
            })
            .collect::<Vec<_>>();

        // Don't stop at the first error.
        let mut bad = Vec::new();
        let mut missing = Vec::new();
        let mut kas = Vec::new();
        for kh in khs {
            if let Some(ka) = vc.keys().key_handle(kh.clone()).next() {
                // The key is bound to the certificate.

                if only_subkeys && ka.primary() {
                    let err = format!(
                        "Selected key {} is a primary key, not a subkey.",
                        ka.key().fingerprint());
                    weprintln!("{}", err);
                    bad.push(anyhow::anyhow!(err));
                    continue;
                }

                // Make sure it is not hard revoked.
                let mut hard_revoked = false;
                if ! return_hard_revoked {
                    if let RevocationStatus::Revoked(sigs)
                        = ka.revocation_status()
                    {
                        for sig in sigs {
                            let reason = sig.reason_for_revocation();
                            hard_revoked = if let Some((reason, _)) = reason {
                                reason.revocation_type() == RevocationType::Hard
                            } else {
                                true
                            };

                            if hard_revoked {
                                break;
                            }
                        }
                    }
                }

                if hard_revoked {
                    let err = anyhow::anyhow!(
                        "Can't use {}, it is hard revoked",
                        ka.key().fingerprint());
                    weprintln!("{}", err);
                    bad.push(err);
                } else {
                    // Looks good!
                    kas.push(ka);
                }
            } else if let Some(ka)
                = vc.cert().keys().key_handle(kh.clone()).next()
            {
                // See if the key is associated with the certificate
                // in some way.  This isn't enough to return it, but
                // we may be able to generate a better error message.

                let fingerprint = ka.key().fingerprint();

                let err = match ka.with_policy(vc.policy(), vc.time()) {
                    Ok(_) => unreachable!("key magically became usable"),
                    Err(err) => err,
                };

                weprintln!("Selected key {} is unusable: {}.",
                           fingerprint, err);

                bad.push(err);

                self.hint(format_args!(
                    "After checking the integrity of the certificate, you \
                     may be able to repair it using:"))
                    .sq().arg("cert").arg("lint").arg("--fix")
                    .arg_value(
                        match &cert_handle {
                            FileStdinOrKeyHandle::KeyHandle(_kh) => {
                                "--cert"
                            }
                            FileStdinOrKeyHandle::FileOrStdin(_file) => {
                                "--cert-file"
                            }
                        },
                        match &cert_handle {
                            FileStdinOrKeyHandle::KeyHandle(kh) => {
                                kh.to_string()
                            }
                            FileStdinOrKeyHandle::FileOrStdin(file) => {
                                file.path()
                                    .map(|p| p.display().to_string())
                                    .unwrap_or_else(|| "".into())
                            }
                        })
                    .done();
            } else {
                // The key isn't bound to the certificate at all.
                weprintln!("Selected key {} is not part of the certificate.",
                           kh);
                missing.push(kh);
            }
        }

        assert_eq!(keys.len(), kas.len() + missing.len() + bad.len(),
                   "Didn't partition {} keys: {} valid, {} missing, {} bad",
                   keys.len(), kas.len(), missing.len(), bad.len());

        if ! missing.is_empty() {
            weprintln!();
            if only_subkeys {
                weprintln!("{} has the following subkeys:", vc.cert().fingerprint());
            } else {
                weprintln!("{} has the following keys:", vc.cert().fingerprint());
            }
            weprintln!();
            for ka in vc.keys().skip(if only_subkeys { 1 } else { 0 }) {
                weprintln!(" - {}", ka.key().fingerprint());
            }
        }

        if let Some(err) = bad.into_iter().next() {
            return Err(err);
        } else if ! missing.is_empty() {
            return Err(anyhow::anyhow!(
                "Some keys are not associated with the certificate"));
        }

        // Dedup.
        kas.sort_by_key(|ka| ka.key().fingerprint());
        kas.dedup_by_key(|ka| ka.key().fingerprint());

        assert!(kas.len() > 0);

        Ok(kas)
    }
}
