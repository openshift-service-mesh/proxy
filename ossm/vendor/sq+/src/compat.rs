//! Improves compatibility with legacy installations.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};

use rusqlite::{Connection, OpenFlags};

use sequoia_openpgp::{
    self as openpgp,
    cert::raw::{RawCert, RawCertParser},
    parse::Parse,
    types::HashAlgorithm,
};

use sequoia_cert_store::{
    CertStore,
    LazyCert,
    StoreUpdate,
};

use crate::{
    Sq,
    print_error_chain,
};

/// Controls tracing in this module.
const TRACE: bool = false;

/// Computes the default home directory.
pub fn gnupghome() -> Result<PathBuf> {
    platform! {
        unix => {
            Ok(dirs::home_dir()
               .ok_or(anyhow::anyhow!("unsupported platform"))?
               .join(".gnupg"))
        },
        windows => {
            Err(anyhow::anyhow!("locating GnuPG's state on Windows \
                                 is not supported"))
        },
    }
}

/// Syncs certificates from GnuPG.
pub fn sync_from_gnupg<'store>(sq: &Sq, cert_store: &CertStore<'store>)
                               -> Result<()> {
    tracer!(TRACE, "sync_from_gnupg");

    let overlay = if let Some(certd) = cert_store.certd() {
        Overlay {
            path: certd.certd().base_dir().into(),
        }
    } else {
        t!("no certd in cert store");
        return Ok(());
    };

    let home = match gnupghome() {
        Ok(h) => h,
        Err(e) => {
            t!("locating GNUPGHOME failed: {}", e);
            return Ok(());
        },
    };

    let resources = [
        Resource {
            kind: Kind::Keybox,
            path: home.join("pubring.kbx"),
        },

        Resource {
            kind: Kind::Keyring,
            path: home.join("pubring.gpg"),
        },

        Resource {
            kind: Kind::KeyboxDB,
            path: home.join("public-keys.d").join("pubring.db"),
        },
    ];

    for resource in resources {
        if ! resource.path.exists() {
            t!("{}: skipping non-existing resource", resource.path.display());
            continue;
        }

        let f = fs::File::open(&resource.path);
        let modified = match &f {
            Ok(f) => Some(f.metadata()?.modified()?),
            Err(_) => None,
        };
        t!("{}: last modified {:?}", resource.path.display(), modified);

        // Get rid of sub-second precision, filetime doesn't seem
        // to set them reliably on Linux.
        let unix_time = |t: SystemTime| {
            t.duration_since(UNIX_EPOCH).unwrap().as_secs()
        };

        if overlay.get_cached_mtime(&resource).ok()
            .map(|cached| modified.map(unix_time) == Some(unix_time(cached)))
            .unwrap_or(false)
        {
            // The overlay already contains all data from
            // this resource.
            t!("{}: skipping up-to-date resource", resource.path.display());
            continue;
        }

        let certs = match resource.kind {
            Kind::Keyring => {
                initialize_keyring(sq, f?, &resource.path)
                    .with_context(|| format!(
                        "Reading the keyring {:?}", resource.path))
            },
            Kind::Keybox => {
                initialize_keybox(sq, f?, &resource.path)
                    .with_context(|| format!(
                        "Reading the keybox {:?}", resource.path))
            },
            Kind::KeyboxX509 => {
                t!("ignoring keybox {:?} only used fox X509",
                   resource.path);
                Ok(Vec::new())
            },
            Kind::KeyboxDB => {
                initialize_keybox_db(&resource.path)
                    .with_context(|| format!(
                        "{}: reading the keybox database",
                        resource.path.display()))
            },
        };

        match certs {
            Ok(certs) => {
                for cert in certs.into_iter() {
                    let keyid = cert.keyid();
                    if let Err(err) = cert_store.update(Arc::new(cert)) {
                        if sq.verbose() {
                            let err = anyhow::Error::from(err)
                                .context(format!(
                                    "Reading {} from {:?}",
                                    keyid, resource.path));
                            print_error_chain(&err);
                        }

                        continue;
                    }
                }
            }
            Err(err) => if sq.verbose() {
                print_error_chain(&err);
            },
        }

        if let Some(modified) = modified {
            overlay.set_cached_mtime(&resource, modified)?;
        }
    }

    Ok(())
}

#[derive(Clone)]
struct Resource {
    kind: Kind,
    path: PathBuf,
}

#[derive(PartialEq, Eq, Clone, Copy)]
#[allow(dead_code)]
pub enum Kind {
    Keybox,
    KeyboxX509,
    KeyboxDB,
    Keyring,
}

/// Initialize a keyring.
fn initialize_keyring<'store, P>(sq: &Sq, file: fs::File, path: P)
                                 -> Result<Vec<LazyCert<'store>>>
where
    P: AsRef<Path>,
{
    tracer!(TRACE, "KeyDB::initialize_keyring");
    let path = path.as_ref();
    t!("loading keyring {:?}", path);

    let results = {
        let iter = match RawCertParser::from_reader(file) {
            Ok(iter) => iter,
            Err(err) => {
                if sq.verbose() {
                    let err = anyhow::Error::from(err).context(
                        format!("Loading keyring {:?}", path));
                    print_error_chain(&err);
                    return Err(err);
                } else {
                    return Err(err);
                }
            }
        };

        iter.filter_map(|cert| {
            match cert {
                Ok(cert) => Some(LazyCert::from(cert)),
                Err(err) => {
                    if sq.verbose() {
                        let err = anyhow::Error::from(err).context(format!(
                            "While parsing cert from keyring {:?}", path));
                        print_error_chain(&err);
                    }

                    None
                }
            }
        }).collect()
    };

    Ok(results)
}

/// Initialize a keybox.
fn initialize_keybox<'store, P>(sq: &Sq, file: fs::File, path: P)
                                -> Result<Vec<LazyCert<'store>>>
where
    P: AsRef<Path>,
{
    use sequoia_ipc::keybox::*;

    tracer!(TRACE, "KeyDB::initialize_keybox");
    let path = path.as_ref();
    t!("loading keybox {:?}", path);

    let iter = match Keybox::from_reader(file) {
        Ok(iter) => iter,
        Err(err) => {
            if sq.verbose() {
                let err = anyhow::Error::from(err).context(format!(
                    "While opening keybox at {:?}", path));
                print_error_chain(&err);
                return Err(err);
            } else {
                return Err(err);
            }
        }
    };

    let results = iter.filter_map(|record| {
        let record = match record {
            Ok(record) => record,
            Err(err) => {
                if sq.verbose() {
                    let err = anyhow::Error::from(err).context(format!(
                        "While parsing a record from keybox {:?}", path));
                    print_error_chain(&err);
                }

                return None;
            }
        };

        if let KeyboxRecord::OpenPGP(record) = record {
            match record.cert() {
                Ok(cert) => Some(LazyCert::from(cert)),
                Err(err) => {
                    if sq.verbose() {
                        let err = anyhow::Error::from(err).context(format!(
                            "While parsing a cert from keybox {:?}", path));
                        print_error_chain(&err);
                    }

                    None
                }
            }
        } else {
            None
        }
    }).collect();

    Ok(results)
}

/// Initialize a keybox database.
fn initialize_keybox_db<'store, P>(path: P)
                                   -> Result<Vec<LazyCert<'store>>>
where
    P: AsRef<Path>,
{
    tracer!(TRACE, "KeyDB::initialize_keybox_db");
    let path = path.as_ref();
    t!("loading keybox database at {}", path.display());

    let conn = Connection::open_with_flags(
        &path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;

    let mut stmt = conn.prepare("SELECT keyblob \
                                 FROM pubkey \
                                 WHERE type = 1")?;

    let certs = stmt.query_map([], |row| Ok(row.get::<_, Vec<u8>>(0)?))?
        .filter_map(|bytes| {
            let bytes = std::io::Cursor::new(bytes.ok()?);
            let cert = RawCert::from_reader(bytes).ok()?;
            t!("loaded {}", cert.fingerprint());
            Some(cert.into())
        })
        .collect();
    drop(stmt);

    Ok(certs)
}

/// Stores metadata in the certd.
pub struct Overlay {
    path: PathBuf,
}

impl Overlay {
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn mtime_cache_path(&self, of: &Resource) -> PathBuf {
        let mut hash = HashAlgorithm::SHA256.context()
            .expect("MTI hash algorithm")
            .for_digest();
        hash.update(of.path.to_string_lossy().as_bytes());

        let name = format!(
            "_sequoia_gpg_chameleon_mtime_{}",
            openpgp::fmt::hex::encode(
                hash.into_digest().expect("SHA2 is complete")));

        self.path().join(name)
    }

    fn get_cached_mtime(&self, of: &Resource) -> Result<SystemTime> {
        Ok(std::fs::metadata(self.mtime_cache_path(&of))?.modified()?)
    }

    fn set_cached_mtime(&self, of: &Resource, new: SystemTime)
                        -> Result<()> {
        // Make sure the overlay exists.  If we fail to create the
        // directory, caching the mtime would fail anyway, and callers
        // of this function expect a side-effect, so this seems like
        // an okay place to do that.
        std::fs::create_dir_all(self.path())?;

        let p = self.mtime_cache_path(&of);
        let f = tempfile::NamedTempFile::new_in(self.path())?;
        filetime::set_file_mtime(f.path(), new.into())?;
        f.persist(p)?;
        Ok(())
    }
}
