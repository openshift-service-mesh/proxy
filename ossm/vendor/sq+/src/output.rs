//! Data types for output format and format version choice.
//!
//! These data types express the values of the `--output-format` and
//! `--output-version` global options to `sq`.

use std::io::Write;

use anyhow::{anyhow, Result};

pub mod hint;
pub mod import;
pub mod pluralize;
pub mod sanitize;
pub mod wrapping;

pub use keyring::ListItem as KeyringListItem;

use crate::cli::types::Version;

pub const DEFAULT_OUTPUT_VERSION: Version = Version::new(0, 0, 0);
pub const OUTPUT_VERSIONS: &[Version] = &[Version::new(0, 0, 0)];

/// A model for the output of `sq` subcommands.
///
/// This is for adding machine-readable output (such as JSON) to
/// subcommand. Every subcommand is represented as a variant, for each
/// version of the output. Versioning is global. We keep the latest
/// subversion of each major version.
///
/// Each variant is created by a dedicated function.
pub enum Model {
    KeyringListV0(keyring::ListV0),
}

impl Model {

    fn version(v: Option<Version>) -> Version {
        v.unwrap_or(DEFAULT_OUTPUT_VERSION)
    }

    /// Create a model for the output of the `sq keyring list`
    /// subcommand.
    pub fn keyring_list(certs: Vec<keyring::ListItem>, all_uids: bool) -> Result<Self> {
        let version = Self::version(None);
        let result = match version {
            keyring::ListV0::V => Self::KeyringListV0(keyring::ListV0::new(certs, all_uids)),
            _ => return Err(anyhow!("unknown output version {:?}", version)),
        };
        Ok(result)
    }

    /// Write the output of a model to an open write handle in the
    /// format requested by the user.
    pub fn write(&self, w: &mut dyn Write) -> Result<()> {
        match self {
            Self::KeyringListV0(x) => x.human_readable(w)?
        }
        Ok(())
    }
}

// Model output as a data type that can be serialized.
mod keyring {
    use sequoia_openpgp as openpgp;
    use openpgp::{
        Result,
        cert::Cert,
    };
    use crate::Sq;
    use crate::common::ui;
    use super::{Version, Write};
    use serde::Serialize;

    #[derive(Debug, Serialize)]
    pub struct ListV0 {
        #[serde(skip)]
        all_uids: bool,
        sq_output_version: Version,
        keys: Vec<ListItem>,
    }

    impl ListV0 {
        pub const V: Version = Version::new(0, 0, 0);

        pub fn new(keys: Vec<ListItem>, all_uids: bool) -> Self {
            Self {
                all_uids,
                sq_output_version: Self::V,
                keys,
            }
        }

        pub fn human_readable(&self, w: &mut dyn Write) -> Result<()> {
            for (i, item) in self.keys.iter().enumerate() {
                match item {
                    ListItem::Error(e) => {
                        writeln!(w, "{}. {}", i, e)?;
                    },
                    ListItem::Cert(cert) => {
                        let line = format!("{}. {}", i, cert.fingerprint);
                        let indent = line.chars().map(|_| ' ').collect::<String>();
                        write!(w, "{}", line)?;
                        match &cert.primary_userid {
                            Some(uid) => writeln!(w, " {}", uid)?,
                            None => writeln!(w)?,
                        }
                        if self.all_uids {
                            for uid in &cert.userids {
                                writeln!(w, "{} {}", indent, uid)?;
                            }
                        }
                    }
                }
            }
            Ok(())
        }
    }

    #[derive(Debug, Serialize)]
    #[serde(untagged)]
    pub enum ListItem {
        Error(String),
        Cert(OutputCert),
    }

    impl ListItem {
        pub fn from_cert_with_sq(item: Result<Cert>, sq: &Sq) -> Self {
            match item {
                Ok(cert) => ListItem::Cert(OutputCert::from_cert_with_sq(cert, sq)),
                Err(e) => ListItem::Error(format!("{}", e)),
            }
        }
    }

    #[derive(Debug, Serialize)]
    pub struct OutputCert {
        fingerprint: String,
        primary_userid: Option<String>,
        userids: Vec<String>,
    }

    impl OutputCert {
        fn from_cert_with_sq(cert: Cert, sq: &Sq) -> Self {
            // Try to be more helpful by including a User ID in the
            // listing.  We'd like it to be the primary one.  Use
            // decreasingly strict policies.
            let mut primary_uid: Option<Vec<u8>> = None;

            // First, apply our policy.
            if let Ok(vcert) = cert.with_policy(sq.policy, None) {
                if let Ok(primary) = vcert.primary_userid() {
                    primary_uid = Some(primary.userid().value().to_vec());
                }
            }

            // Second, apply the null policy.
            if primary_uid.is_none() {
                let null = unsafe { openpgp::policy::NullPolicy::new() };
                if let Ok(vcert) = cert.with_policy(&null, None) {
                    if let Ok(primary) = vcert.primary_userid() {
                        primary_uid = Some(primary.userid().value().to_vec());
                    }
                }
            }

            // As a last resort, pick the first user id.
            if primary_uid.is_none() {
                if let Some(primary) = cert.userids().next() {
                    primary_uid = Some(primary.userid().value().to_vec());
                }
            }

            // List all user ids independently of their validity.
            let mut userids = vec![];
            for u in cert.userids() {
                if primary_uid.as_ref()
                    .map(|p| &p[..] == u.userid().value()).unwrap_or(false)
                {
                    // Skip the user id we already handled.
                    continue;
                }

                userids.push(Self::userid(u.userid().value()));
            }

            Self {
                fingerprint: format!("{:X}", cert.fingerprint()),
                primary_userid: primary_uid.map(|id| Self::userid(&id)),
                userids,
            }
        }

        fn userid(bytes: &[u8]) -> String {
            ui::Safe(bytes).to_string()
        }
    }
}
