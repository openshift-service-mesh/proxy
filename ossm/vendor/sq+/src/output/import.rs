//! Certificate and key import stats.

use std::{
    fmt,
    sync::Arc,
};

use anyhow::Result;

use sequoia_cert_store::{
    LazyCert,
    store::{
        MergeCerts,
        MergePublicCollectStats,
    },
};

use sequoia_keystore as keystore;

use crate::output::pluralize::Pluralize;

/// Certificate and key import stats.
#[derive(Debug)]
pub struct ImportStats {
    pub certs: MergePublicCollectStats,
    pub keys: KeyStats,
}

impl Default for ImportStats {
    fn default() -> Self {
        ImportStats {
            certs: MergePublicCollectStats::new(),
            keys: Default::default(),
        }
    }
}

impl std::ops::AddAssign for ImportStats {
    fn add_assign(&mut self, other: Self) {
        // XXX: Not ideal.
        (0..other.certs.new_certs())
            .for_each(|_| self.certs.inc_new_certs());
        (0..other.certs.unchanged_certs())
            .for_each(|_| self.certs.inc_unchanged_certs());
        (0..other.certs.updated_certs())
            .for_each(|_| self.certs.inc_updated_certs());
        (0..other.certs.errors())
            .for_each(|_| self.certs.inc_errors());
    }
}

impl<'a> MergeCerts<'a> for ImportStats {
    fn merge_public<'b>(
        &self,
        new: Arc<LazyCert<'a>>,
        disk: Option<Arc<LazyCert<'b>>>,
    ) -> Result<Arc<LazyCert<'a>>> {
        self.certs.merge_public(new, disk)
    }
}

impl ImportStats {
    /// Print key and certificate import summary.
    pub fn print_summary(&self, o: &mut dyn std::io::Write, sq: &crate::Sq)
        -> Result<()>
    {
        if sq.quiet() {
            return Ok(());
        }

        if ! self.keys.is_empty() {
            self.keys.print_summary(o)?;
        }

        wwriteln!(o,
                  "Imported {}, updated {}, {} unchanged, {}.",
                  self.certs.new_certs().of("new certificate"),
                  self.certs.updated_certs().of("certificate"),
                  self.certs.unchanged_certs().of("certificate"),
                  self.certs.errors().of("error"));
        Ok(())
    }
}

/// Key import stats.
#[derive(Debug, Default)]
pub struct KeyStats {
    /// Number of new keys.
    pub new: usize,

    /// Number of unchanged keys.
    pub unchanged: usize,

    /// Number of updated keys.
    pub updated: usize,

    /// Number of errors.
    pub errors: usize,
}

impl std::ops::AddAssign for KeyStats {
    fn add_assign(&mut self, other: Self) {
        self.new += other.new;
        self.unchanged += other.unchanged;
        self.updated += other.updated;
        self.errors += other.errors;
    }
}

impl KeyStats {
    /// Returns whether there haven't been any key imports at all.
    pub fn is_empty(&self) -> bool {
        self.new == 0
            && self.unchanged == 0
            && self.updated == 0
            && self.errors == 0
    }

    /// Print key and certificate import summary.
    pub fn print_summary(&self, o: &mut dyn std::io::Write) -> Result<()> {
        wwriteln!(o,
                  "Imported {}, updated {}, {} unchanged, {}.",
                  self.new.of("new key"),
                  self.updated.of("key"),
                  self.unchanged.of("key"),
                  self.errors.of("error"));
        Ok(())
    }
}

/// Whether a cert or key was freshly imported, updated, or unchanged.
///
/// Returned by [`Sq::import_key`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ImportStatus {
    /// The certificate or key is unchanged.
    Unchanged,

    /// The certificate or key is new.
    New,

    /// The certificate or key has been updated.
    Updated,
}

impl From<keystore::ImportStatus> for ImportStatus {
    fn from(status: keystore::ImportStatus) -> ImportStatus {
        match status {
            keystore::ImportStatus::Unchanged => ImportStatus::Unchanged,
            keystore::ImportStatus::New => ImportStatus::New,
            keystore::ImportStatus::Updated => ImportStatus::Updated,
        }
    }
}

impl fmt::Display for ImportStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ImportStatus::Unchanged => f.write_str("unchanged"),
            ImportStatus::New => f.write_str("new"),
            ImportStatus::Updated => f.write_str("updated"),
        }
    }
}
